namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP01 - AV/EDR posture: Defender status via WMI + third-party AV detection.
/// </summary>
public sealed class EP01_AvEdrCheck : ISecurityCheck
{
    public string Id => "EP01";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            bool defenderFound = false;

            // -- Defender via WMI --
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, " +
                    "RealTimeProtectionEnabled, AntivirusSignatureAge, " +
                    "AntivirusSignatureLastUpdated, NISEnabled FROM MSFT_MpComputerStatus");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();
                    defenderFound = true;

                    bool amService = GetBool(obj, "AMServiceEnabled");
                    bool antispyware = GetBool(obj, "AntispywareEnabled");
                    bool antivirus = GetBool(obj, "AntivirusEnabled");
                    bool realtime = GetBool(obj, "RealTimeProtectionEnabled");
                    bool nis = GetBool(obj, "NISEnabled");
                    int sigAge = GetInt(obj, "AntivirusSignatureAge");

                    evidence.AppendLine("[Defender Status]");
                    evidence.AppendLine($"  AM Service Enabled:        {amService}");
                    evidence.AppendLine($"  Antispyware Enabled:       {antispyware}");
                    evidence.AppendLine($"  Antivirus Enabled:         {antivirus}");
                    evidence.AppendLine($"  Real-Time Protection:      {realtime}");
                    evidence.AppendLine($"  Network Inspection (NIS):  {nis}");
                    evidence.AppendLine($"  Signature Age (days):      {sigAge}");

                    if (!amService || !antivirus || !realtime)
                    {
                        hasIssue = true;
                        sb.AppendLine("CRITICAL: Windows Defender is not fully enabled.");
                        if (!amService) sb.AppendLine("  - AM Service is disabled.");
                        if (!antivirus) sb.AppendLine("  - Antivirus engine is disabled.");
                        if (!realtime) sb.AppendLine("  - Real-time protection is OFF.");
                    }

                    if (sigAge > 7)
                    {
                        hasIssue = true;
                        sb.AppendLine($"WARNING: Antivirus signatures are {sigAge} days old (>7 days).");
                    }
                    else if (sigAge > 3)
                    {
                        sb.AppendLine($"INFO: Signature age is {sigAge} days (monitor if trending upward).");
                    }

                    if (!antispyware)
                    {
                        sb.AppendLine("WARNING: Antispyware component is disabled.");
                        hasIssue = true;
                    }
                }
            }
            catch (ManagementException)
            {
                sb.AppendLine("Defender WMI namespace not accessible (may be uninstalled or third-party AV is primary).");
            }

            // -- Third-party AV via Security Center (WMI) --
            ct.ThrowIfCancellationRequested();
            var thirdPartyAv = DetectThirdPartyAV(evidence);

            if (thirdPartyAv.Count > 0)
            {
                sb.AppendLine($"Third-party AV detected: {string.Join(", ", thirdPartyAv)}");
            }
            else if (!defenderFound)
            {
                hasIssue = true;
                sb.AppendLine("CRITICAL: No AV/EDR product detected on this system.");
            }

            // -- Check for common EDR agents via registry --
            ct.ThrowIfCancellationRequested();
            var edrProducts = DetectEDR(evidence);
            if (edrProducts.Count > 0)
            {
                sb.AppendLine($"EDR/XDR products detected: {string.Join(", ", edrProducts)}");
            }

            if (sb.Length == 0)
                sb.AppendLine("Windows Defender is fully enabled with current signatures.");

            var status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass;
            if (!defenderFound && thirdPartyAv.Count > 0)
                status = CheckStatus.Partial; // Third-party AV present but can't verify posture

            return Task.FromResult(new CheckResult
            {
                Status = status,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static List<string> DetectThirdPartyAV(StringBuilder evidence)
    {
        var products = new List<string>();
        try
        {
            // SecurityCenter2 namespace (workstations only)
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT displayName, productState FROM AntiVirusProduct");

            evidence.AppendLine("\n[SecurityCenter2 AV Products]");
            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["displayName"]?.ToString() ?? "Unknown";
                uint state = Convert.ToUInt32(obj["productState"] ?? 0);
                var decoded = DecodeSecurityCenterProductState(state);

                evidence.AppendLine(
                    $"  {name}: enabled={decoded.Enabled}, upToDate={decoded.SignaturesUpToDate} " +
                    $"(state=0x{state:X6}, provider=0x{decoded.Provider:X2}, scanner=0x{decoded.ScannerState:X2}, signatures=0x{decoded.SignatureStatus:X2})");

                if (!name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
                    products.Add(name);
            }
        }
        catch
        {
            // SecurityCenter2 not available (servers)
        }

        return products;
    }

    internal static SecurityCenterProductState DecodeSecurityCenterProductState(uint state)
    {
        var provider = (byte)((state >> 16) & 0xFF);
        var scannerState = (byte)((state >> 8) & 0xFF);
        var signatureStatus = (byte)(state & 0xFF);

        return new SecurityCenterProductState(
            provider,
            scannerState,
            signatureStatus,
            Enabled: scannerState is 0x10 or 0x11,
            SignaturesUpToDate: signatureStatus == 0x00);
    }

    internal readonly record struct SecurityCenterProductState(
        byte Provider,
        byte ScannerState,
        byte SignatureStatus,
        bool Enabled,
        bool SignaturesUpToDate);

    private static List<string> DetectEDR(StringBuilder evidence)
    {
        var products = new List<string>();
        var edrSignatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\CrowdStrike", "CrowdStrike Falcon" },
            { @"HKLM\SOFTWARE\SentinelOne", "SentinelOne" },
            { @"HKLM\SOFTWARE\Carbon Black", "VMware Carbon Black" },
            { @"HKLM\SOFTWARE\Cylance", "BlackBerry Cylance" },
            { @"HKLM\SOFTWARE\Sophos", "Sophos" },
            { @"HKLM\SOFTWARE\ESET", "ESET" },
            { @"HKLM\SOFTWARE\Palo Alto Networks", "Cortex XDR" },
            { @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection", "Defender for Endpoint" },
        };

        evidence.AppendLine("\n[EDR/XDR Registry Check]");
        foreach (var (keyPath, label) in edrSignatures)
        {
            if (RegistryHelper.KeyExists(keyPath))
            {
                products.Add(label);
                evidence.AppendLine($"  FOUND: {label} ({keyPath})");
            }
        }

        if (products.Count == 0)
            evidence.AppendLine("  No EDR registry keys detected.");

        return products;
    }

    private static bool GetBool(ManagementObject obj, string prop)
    {
        try { return obj[prop] is true; } catch { return false; }
    }

    private static int GetInt(ManagementObject obj, string prop)
    {
        try { return Convert.ToInt32(obj[prop] ?? 0); } catch { return -1; }
    }
}

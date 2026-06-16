namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP07 - IDS/IPS: Heuristic check for intrusion detection/prevention systems.
/// Check for Snort/Suricata services and firewall IPS features.
/// </summary>
public sealed class NP07_IdsIpsCheck : ISecurityCheck
{
    public string Id => "NP07";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool idsFound = false;

            // 1. Check for IDS/IPS services
            ct.ThrowIfCancellationRequested();
            CheckIdsServices(sb, evidence, ref idsFound, ct);

            // 2. Check for IDS/IPS software via registry
            ct.ThrowIfCancellationRequested();
            CheckIdsSoftware(sb, evidence, ref idsFound);

            // 3. Check Windows Defender Network Inspection Service (NIS)
            ct.ThrowIfCancellationRequested();
            CheckDefenderNis(sb, evidence, ref idsFound);

            // 4. Check for Windows Firewall advanced IPS features
            ct.ThrowIfCancellationRequested();
            CheckFirewallIps(sb, evidence);

            // Summary
            if (idsFound)
            {
                sb.Insert(0, "IDS/IPS capabilities detected.\n");
            }
            else
            {
                sb.Insert(0, "No dedicated IDS/IPS solution detected on this host.\n");
                sb.AppendLine("WARNING: No intrusion detection/prevention system found. " +
                    "Recommend deploying network-based IDS/IPS (Snort, Suricata, or commercial solution) " +
                    "or host-based IPS (EDR with IPS capabilities).");
                sb.AppendLine("NOTE: IDS/IPS may be deployed at the network perimeter (firewall/UTM) " +
                    "rather than on individual hosts. Verify with network infrastructure review.");
            }

            var status = idsFound ? CheckStatus.Pass : CheckStatus.Partial;

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

    private static void CheckIdsServices(StringBuilder sb, StringBuilder evidence,
        ref bool idsFound, CancellationToken ct)
    {
        evidence.AppendLine("[IDS/IPS Service Check]");

        string[] idsServiceNames =
        [
            "snort", "suricata", "ossec", "wazuh", "zeek", "bro",
            "SnortService", "SuricataService"
        ];

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, StartMode FROM Win32_Service");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string name = obj["Name"]?.ToString() ?? "";
                string displayName = obj["DisplayName"]?.ToString() ?? "";

                foreach (string ids in idsServiceNames)
                {
                    if (name.Contains(ids, StringComparison.OrdinalIgnoreCase) ||
                        displayName.Contains(ids, StringComparison.OrdinalIgnoreCase))
                    {
                        idsFound = true;
                        string state = obj["State"]?.ToString() ?? "Unknown";
                        evidence.AppendLine($"  FOUND: {displayName} ({name}) - State: {state}");
                        sb.AppendLine($"IDS/IPS service detected: {displayName} ({state})");
                        break;
                    }
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckIdsSoftware(StringBuilder sb, StringBuilder evidence, ref bool idsFound)
    {
        evidence.AppendLine("\n[IDS/IPS Software Registry]");

        var idsSoftware = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Snort", "Snort" },
            { @"HKLM\SOFTWARE\OISF\Suricata", "Suricata" },
            { @"HKLM\SOFTWARE\OSSEC", "OSSEC" },
            { @"HKLM\SOFTWARE\Wazuh", "Wazuh" },
            { @"HKLM\SOFTWARE\AlienVault", "AlienVault OSSIM" },
            { @"HKLM\SOFTWARE\Trend Micro\Deep Security Agent", "Trend Micro Deep Security" },
            { @"HKLM\SOFTWARE\McAfee\NSP", "McAfee Network Security" },
        };

        bool foundAny = false;
        foreach (var (path, label) in idsSoftware)
        {
            if (RegistryHelper.KeyExists(path))
            {
                foundAny = true;
                idsFound = true;
                evidence.AppendLine($"  FOUND: {label} ({path})");
                sb.AppendLine($"IDS/IPS software detected: {label}");
            }
        }

        if (!foundAny)
            evidence.AppendLine("  No IDS/IPS software registry keys detected.");
    }

    private static void CheckDefenderNis(StringBuilder sb, StringBuilder evidence, ref bool idsFound)
    {
        evidence.AppendLine("\n[Windows Defender Network Inspection]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT NISEnabled, NISSignatureAge, NISEngineVersion FROM MSFT_MpComputerStatus");

            foreach (ManagementObject obj in searcher.Get())
            {
                bool nisEnabled = obj["NISEnabled"] is true;
                string engineVer = obj["NISEngineVersion"]?.ToString() ?? "Unknown";
                int sigAge = 0;
                try { sigAge = Convert.ToInt32(obj["NISSignatureAge"] ?? 0); } catch { }

                evidence.AppendLine($"  NIS Enabled: {nisEnabled}");
                evidence.AppendLine($"  NIS Engine: {engineVer}");
                evidence.AppendLine($"  NIS Signature Age: {sigAge} days");

                if (nisEnabled)
                {
                    idsFound = true;
                    sb.AppendLine($"Windows Defender Network Inspection Service (NIS) is enabled (engine: {engineVer}).");
                }
            }
        }
        catch (ManagementException)
        {
            evidence.AppendLine("  Defender WMI not accessible.");
        }
    }

    private static void CheckFirewallIps(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[Windows Firewall IPsec]");

        // Check for IPsec connection security rules (not IPS per se, but related)
        bool hasIpsec = RegistryHelper.KeyExists(
            @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules");

        evidence.AppendLine($"  IPsec connection security rules configured: {hasIpsec}");

        if (hasIpsec)
            sb.AppendLine("INFO: IPsec connection security rules are configured.");
    }
}

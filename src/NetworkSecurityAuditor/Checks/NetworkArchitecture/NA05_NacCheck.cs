namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Management;
using System.Text;
using Microsoft.Win32;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NA05 - 802.1X/NAC: Check for 802.1X authentication on wired adapters,
/// NPS/RADIUS service, and Dot3Svc service status.
/// </summary>
public sealed class NA05_NacCheck : ISecurityCheck
{
    public string Id => "NA05";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool dot1xEnabled = false;
            bool npsFound = false;

            // 1. Check Dot3Svc (Wired AutoConfig) service status
            ct.ThrowIfCancellationRequested();
            CheckDot3Service(sb, evidence, ref dot1xEnabled, ct);

            // 2. Check 802.1X registry configuration
            ct.ThrowIfCancellationRequested();
            Check8021xRegistry(sb, evidence, ref dot1xEnabled);

            // 3. Check for NPS/RADIUS service (IAS)
            ct.ThrowIfCancellationRequested();
            CheckNpsService(sb, evidence, ref npsFound, ct);

            // 4. Check for NAC agent software
            ct.ThrowIfCancellationRequested();
            CheckNacAgents(sb, evidence);

            // Summary
            if (dot1xEnabled)
            {
                sb.Insert(0, "802.1X wired authentication is configured on this system.\n");
            }
            else
            {
                sb.Insert(0, "802.1X wired authentication does not appear to be enabled.\n");
                sb.AppendLine("WARNING: Without 802.1X, any device can connect to the wired network. " +
                    "Recommend implementing 802.1X port-based authentication.");
            }

            var status = dot1xEnabled ? CheckStatus.Pass
                : npsFound ? CheckStatus.Partial
                : CheckStatus.Fail;

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

    private static void CheckDot3Service(StringBuilder sb, StringBuilder evidence,
        ref bool dot1xEnabled, CancellationToken ct)
    {
        evidence.AppendLine("[Dot3Svc (Wired AutoConfig) Service]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'dot3svc'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                string startMode = obj["StartMode"]?.ToString() ?? "Unknown";

                evidence.AppendLine($"  State: {state}, StartMode: {startMode}");

                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    dot1xEnabled = true;
                    sb.AppendLine("Dot3Svc (Wired AutoConfig) is running - 802.1X capable.");
                }
                else
                {
                    sb.AppendLine($"Dot3Svc service is {state} (StartMode: {startMode}). " +
                        "802.1X wired authentication requires this service running.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void Check8021xRegistry(StringBuilder sb, StringBuilder evidence, ref bool dot1xEnabled)
    {
        evidence.AppendLine("\n[802.1X Registry Configuration]");

        // Check for 802.1X profile configuration
        string profilePath = @"HKLM\SOFTWARE\Microsoft\dot3svc\Profiles";
        var profiles = RegistryHelper.GetSubKeyNames(profilePath);

        if (profiles.Length > 0)
        {
            dot1xEnabled = true;
            evidence.AppendLine($"  802.1X profiles found: {profiles.Length}");
            foreach (string p in profiles.Take(10))
                evidence.AppendLine($"    {p}");
            sb.AppendLine($"802.1X wired profiles configured: {profiles.Length}");
        }
        else
        {
            evidence.AppendLine("  No 802.1X wired profiles found.");
        }

        // Check EAP method configuration
        string eapPath = @"HKLM\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP";
        var eapMethods = RegistryHelper.GetSubKeyNames(eapPath);
        if (eapMethods.Length > 0)
        {
            evidence.AppendLine($"  EAP methods registered: {eapMethods.Length}");
        }
    }

    private static void CheckNpsService(StringBuilder sb, StringBuilder evidence,
        ref bool npsFound, CancellationToken ct)
    {
        evidence.AppendLine("\n[NPS/RADIUS Service Check]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'IAS'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                string startMode = obj["StartMode"]?.ToString() ?? "Unknown";

                npsFound = true;
                evidence.AppendLine($"  NPS/IAS Service - State: {state}, StartMode: {startMode}");
                sb.AppendLine($"NPS/RADIUS service found: {state} ({startMode}).");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        if (!npsFound)
            evidence.AppendLine("  NPS/IAS service not found on this host.");
    }

    private static void CheckNacAgents(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[NAC Agent Software]");

        var nacSoftware = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Cisco\CiscoISE", "Cisco ISE" },
            { @"HKLM\SOFTWARE\Cisco\AnyConnect", "Cisco AnyConnect" },
            { @"HKLM\SOFTWARE\Aruba Networks", "Aruba ClearPass" },
            { @"HKLM\SOFTWARE\ForeScout", "ForeScout CounterACT" },
            { @"HKLM\SOFTWARE\Bradford Networks", "Bradford NAC" },
            { @"HKLM\SOFTWARE\Portnox", "Portnox" },
        };

        bool foundAny = false;
        foreach (var (path, label) in nacSoftware)
        {
            if (RegistryHelper.KeyExists(path))
            {
                foundAny = true;
                evidence.AppendLine($"  FOUND: {label} ({path})");
                sb.AppendLine($"NAC agent detected: {label}");
            }
        }

        if (!foundAny)
            evidence.AppendLine("  No NAC agent software detected.");
    }
}

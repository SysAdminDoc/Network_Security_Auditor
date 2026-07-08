namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Management;
using System.Net;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NA02 - VLAN Configuration: Query network adapters for VLAN IDs and check static routes
/// indicating inter-VLAN routing.
/// </summary>
public sealed class NA02_VlanCheck : ISecurityCheck
{
    public string Id => "NA02";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasVlan = false;
            bool hasInterVlanRouting = false;

            // 1. Check for VLAN-tagged adapters via WMI
            ct.ThrowIfCancellationRequested();
            CheckVlanAdapters(sb, evidence, ref hasVlan, ct);

            // 2. Check registry for VLAN configuration (common NIC teaming/VLAN drivers)
            ct.ThrowIfCancellationRequested();
            CheckVlanRegistry(sb, evidence, ref hasVlan);

            // 3. Check static routes for inter-VLAN routing indicators
            ct.ThrowIfCancellationRequested();
            CheckStaticRoutes(sb, evidence, ref hasInterVlanRouting, ct);

            // 4. Summarize
            if (hasVlan)
            {
                sb.Insert(0, "VLAN configuration detected on this host.\n");
                if (hasInterVlanRouting)
                    sb.AppendLine("INFO: Static routes suggest inter-VLAN routing is configured on this host.");
            }
            else
            {
                sb.Insert(0, "No VLAN tagging detected on local adapters.\n");
                sb.AppendLine("NOTE: VLAN configuration is typically managed on switches/routers. " +
                    "Verify VLAN segmentation at the network infrastructure level.");
            }

            var status = hasVlan ? CheckStatus.Pass : CheckStatus.Partial;

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

    private static void CheckVlanAdapters(StringBuilder sb, StringBuilder evidence, ref bool hasVlan, CancellationToken ct)
    {
        evidence.AppendLine("[Network Adapter VLAN Check]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Description, Name, NetConnectionID FROM Win32_NetworkAdapter WHERE NetConnectionStatus = 2");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string desc = obj["Description"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";
                string connId = obj["NetConnectionID"]?.ToString() ?? "";

                evidence.AppendLine($"  Adapter: {desc} ({connId})");

                // Check if adapter name/description contains VLAN indicators
                if (desc.Contains("VLAN", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("VLAN", StringComparison.OrdinalIgnoreCase) ||
                    connId.Contains("VLAN", StringComparison.OrdinalIgnoreCase))
                {
                    hasVlan = true;
                    sb.AppendLine($"VLAN adapter found: {desc} ({connId})");
                    evidence.AppendLine($"    -> VLAN indicator in adapter name");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckVlanRegistry(StringBuilder sb, StringBuilder evidence, ref bool hasVlan)
    {
        evidence.AppendLine("\n[VLAN Registry Check]");

        // Intel VLAN driver
        string[] vlanRegPaths =
        [
            @"HKLM\SYSTEM\CurrentControlSet\Services\intelvlan",
            @"HKLM\SYSTEM\CurrentControlSet\Services\BroadcomVLAN",
            @"HKLM\SYSTEM\CurrentControlSet\Services\MsLbfoProvider",
        ];

        foreach (string path in vlanRegPaths)
        {
            if (Services.RegistryHelper.KeyExists(path))
            {
                hasVlan = true;
                evidence.AppendLine($"  FOUND: {path}");
                sb.AppendLine($"VLAN driver/service detected: {path}");
            }
        }

        // NIC Teaming (LBFO) with VLAN
        var lbfoTeams = Services.RegistryHelper.GetSubKeyNames(
            @"HKLM\SYSTEM\CurrentControlSet\Services\MsLbfoProvider\Parameters\Teams");
        if (lbfoTeams.Length > 0)
        {
            evidence.AppendLine($"  NIC Teaming (LBFO) teams: {string.Join(", ", lbfoTeams)}");
        }
    }

    private static void CheckStaticRoutes(StringBuilder sb, StringBuilder evidence,
        ref bool hasInterVlanRouting, CancellationToken ct)
    {
        evidence.AppendLine("\n[Static Route Analysis]");

        try
        {
            string output = CommandRunner.RunForOutput("route", "print", TimeSpan.FromSeconds(15), ct);

            int persistentRoutes = 0;
            bool inPersistent = false;

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();

                if (trimmed.Contains("Persistent Routes", StringComparison.OrdinalIgnoreCase))
                {
                    inPersistent = true;
                    continue;
                }

                if (inPersistent && !string.IsNullOrWhiteSpace(trimmed) &&
                    !trimmed.StartsWith("Network", StringComparison.OrdinalIgnoreCase) &&
                    !trimmed.StartsWith("===") && !trimmed.StartsWith("None"))
                {
                    var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3 && IPAddress.TryParse(parts[0], out _))
                    {
                        persistentRoutes++;
                        evidence.AppendLine($"  Persistent route: {trimmed}");
                        hasInterVlanRouting = true;
                    }
                }
            }

            evidence.AppendLine($"  Persistent static routes found: {persistentRoutes}");

            if (persistentRoutes > 0)
            {
                sb.AppendLine($"Found {persistentRoutes} persistent static route(s) - may indicate inter-VLAN or multi-subnet routing.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Route query error: {ex.Message}");
        }
    }
}

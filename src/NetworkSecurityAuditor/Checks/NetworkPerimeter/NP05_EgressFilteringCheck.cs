namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP05 - Egress Filtering: Check outbound firewall rules. Look for default "Allow All"
/// outbound. Count outbound block rules.
/// </summary>
public sealed class NP05_EgressFilteringCheck : ISecurityCheck
{
    public string Id => "NP05";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            int totalOutbound = 0;
            int outboundAllow = 0;
            int outboundBlock = 0;
            int anyAnyAllow = 0;

            // 1. Check default outbound action per profile
            ct.ThrowIfCancellationRequested();
            CheckDefaultOutbound(sb, evidence, ref hasIssue);

            // 2. Enumerate outbound rules
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Outbound Firewall Rules]");

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\StandardCimv2",
                    "SELECT InstanceID, ElementName, Direction, Action, " +
                    "LocalPort, RemotePort, RemoteAddress, Protocol, Enabled " +
                    "FROM MSFT_NetFirewallRule WHERE Enabled = 1");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();

                    int direction = Convert.ToInt32(obj["Direction"] ?? 0);
                    if (direction != 2) continue; // 2 = Outbound

                    totalOutbound++;
                    int action = Convert.ToInt32(obj["Action"] ?? 0);

                    if (action == 2) // Allow
                    {
                        outboundAllow++;

                        string? remotePort = obj["RemotePort"]?.ToString();
                        string? remoteAddr = obj["RemoteAddress"]?.ToString();

                        bool isAnyPort = string.IsNullOrEmpty(remotePort) || remotePort == "Any" || remotePort == "*";
                        bool isAnyAddr = string.IsNullOrEmpty(remoteAddr) || remoteAddr == "Any" || remoteAddr == "*";

                        if (isAnyPort && isAnyAddr)
                        {
                            anyAnyAllow++;
                            string name = obj["ElementName"]?.ToString() ?? obj["InstanceID"]?.ToString() ?? "Unknown";
                            evidence.AppendLine($"  ANY/ANY ALLOW OUT: {name}");
                        }
                    }
                    else if (action == 4) // Block
                    {
                        outboundBlock++;
                    }
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
                // Fallback handled by default outbound check
            }

            evidence.AppendLine($"\n  Summary: {totalOutbound} outbound rules, " +
                $"{outboundAllow} allow, {outboundBlock} block, {anyAnyAllow} any/any allow");

            sb.AppendLine($"Outbound firewall rules: {totalOutbound} total, {outboundAllow} allow, {outboundBlock} block.");

            if (outboundBlock == 0 && totalOutbound > 0)
            {
                hasIssue = true;
                sb.AppendLine("WARNING: No outbound block rules found. Without egress filtering, " +
                    "malware can freely communicate with command-and-control servers.");
            }

            if (anyAnyAllow > 3)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {anyAnyAllow} outbound ALLOW rules with no port/address restriction. " +
                    "Recommend implementing application-aware egress filtering.");
            }

            if (!hasIssue)
                sb.AppendLine("Egress filtering appears configured with outbound block rules.");

            var status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass;

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

    private static void CheckDefaultOutbound(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("[Default Outbound Action per Profile]");

        string[] profiles = ["DomainProfile", "StandardProfile", "PublicProfile"];
        string basePath = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        foreach (string profile in profiles)
        {
            string path = $@"{basePath}\{profile}";
            int defaultOutbound = Services.RegistryHelper.GetValue<int>(path, "DefaultOutboundAction", -1);

            string action = defaultOutbound switch
            {
                0 => "Allow (default)",
                1 => "Block",
                _ => "Unknown"
            };

            evidence.AppendLine($"  {profile}: DefaultOutboundAction = {action}");

            if (defaultOutbound == 0)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {profile} default outbound action is ALLOW. " +
                    "Best practice is to set default outbound to BLOCK and whitelist required traffic.");
            }
            else if (defaultOutbound == 1)
            {
                sb.AppendLine($"{profile}: Default outbound is BLOCK (good).");
            }
        }
    }
}

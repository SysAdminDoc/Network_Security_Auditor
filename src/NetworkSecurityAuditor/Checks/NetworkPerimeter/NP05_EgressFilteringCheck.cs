namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

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
                foreach (var rule in FirewallRuleReader.GetEnabledRules(ct))
                {
                    ct.ThrowIfCancellationRequested();

                    if (!rule.IsOutbound) continue;

                    totalOutbound++;

                    if (rule.IsAllow)
                    {
                        outboundAllow++;

                        if (rule.HasAnyRemotePort && rule.HasAnyRemoteAddress)
                        {
                            anyAnyAllow++;
                            evidence.AppendLine($"  ANY/ANY ALLOW OUT: {rule.Name} " +
                                $"(RemotePort={FirewallRuleReader.FormatValues(rule.RemotePorts)}, " +
                                $"RemoteAddr={FirewallRuleReader.FormatValues(rule.RemoteAddresses)})");
                        }
                    }
                    else if (rule.IsBlock)
                    {
                        outboundBlock++;
                    }
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
                QueryOutboundViaNetsh(evidence, ref totalOutbound, ref outboundAllow, ref outboundBlock, ref anyAnyAllow, ct);
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

    private static void QueryOutboundViaNetsh(
        StringBuilder evidence,
        ref int totalOutbound,
        ref int outboundAllow,
        ref int outboundBlock,
        ref int anyAnyAllow,
        CancellationToken ct)
    {
        try
        {
            string output = CommandRunner.RunForOutput(
                "netsh",
                "advfirewall firewall show rule name=all dir=out",
                TimeSpan.FromSeconds(30),
                ct);

            evidence.AppendLine("  [Parsed from netsh output]");

            string currentName = "";
            bool currentEnabled = false;
            string currentAction = "";
            string currentRemotePort = "";
            string currentRemoteAddr = "";

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    ProcessNetshOutboundRule(evidence, ref totalOutbound, ref outboundAllow, ref outboundBlock,
                        ref anyAnyAllow, currentName, currentEnabled, currentAction, currentRemotePort, currentRemoteAddr);

                    currentName = line[10..].Trim();
                    currentEnabled = false;
                    currentAction = "";
                    currentRemotePort = "";
                    currentRemoteAddr = "";
                }
                else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                {
                    currentEnabled = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                }
                else if (line.StartsWith("Action:", StringComparison.OrdinalIgnoreCase))
                {
                    currentAction = line[7..].Trim();
                }
                else if (line.StartsWith("RemotePort:", StringComparison.OrdinalIgnoreCase))
                {
                    currentRemotePort = line[11..].Trim();
                }
                else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
                {
                    currentRemoteAddr = line[9..].Trim();
                }
            }

            ProcessNetshOutboundRule(evidence, ref totalOutbound, ref outboundAllow, ref outboundBlock,
                ref anyAnyAllow, currentName, currentEnabled, currentAction, currentRemotePort, currentRemoteAddr);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh fallback error: {ex.Message}");
        }
    }

    private static void ProcessNetshOutboundRule(
        StringBuilder evidence,
        ref int totalOutbound,
        ref int outboundAllow,
        ref int outboundBlock,
        ref int anyAnyAllow,
        string name,
        bool enabled,
        string action,
        string remotePort,
        string remoteAddr)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalOutbound++;

        if (action.Contains("Allow", StringComparison.OrdinalIgnoreCase))
        {
            outboundAllow++;

            if (FirewallRuleReader.IsAnyValue([remotePort]) && FirewallRuleReader.IsAnyValue([remoteAddr]))
            {
                anyAnyAllow++;
                evidence.AppendLine($"  ANY/ANY ALLOW OUT: {name} (RemotePort={ValueOrAny(remotePort)}, RemoteAddr={ValueOrAny(remoteAddr)})");
            }
        }
        else if (action.Contains("Block", StringComparison.OrdinalIgnoreCase))
        {
            outboundBlock++;
        }
    }

    private static string ValueOrAny(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "Any" : value;
    }
}

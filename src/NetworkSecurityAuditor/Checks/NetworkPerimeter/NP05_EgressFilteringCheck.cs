namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Globalization;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP05 - Egress Filtering: Check outbound firewall rules. Look for default "Allow All"
/// outbound. Count outbound block rules. Profiles and rules come from the active store, so
/// Group Policy settings and rules count.
/// </summary>
public sealed class NP05_EgressFilteringCheck : ISecurityCheck
{
    private readonly Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>> _readRules;
    private readonly Func<string, string, CancellationToken, string> _runCommand;
    private readonly Func<IReadOnlyList<OutboundDefault>> _readOutboundDefaults;

    public string Id => "NP05";

    /// <summary>A profile's default outbound action. Blocks is null when it couldn't be read.</summary>
    internal sealed record OutboundDefault(string Profile, bool? Blocks, string Source);

    public NP05_EgressFilteringCheck()
        : this(null, null, null)
    {
    }

    internal NP05_EgressFilteringCheck(
        Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>>? readRules,
        Func<string, string, CancellationToken, string>? runCommand = null,
        Func<IReadOnlyList<OutboundDefault>>? readOutboundDefaults = null)
    {
        _readRules = readRules ?? ((ct, store) => FirewallRuleReader.GetEnabledRules(ct, store));
        _runCommand = runCommand ?? ((file, args, ct) => CommandRunner.RunForOutput(file, args, TimeSpan.FromSeconds(30), ct));
        _readOutboundDefaults = readOutboundDefaults ?? ReadOutboundDefaults;
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            bool localStoreOnly = false;

            int totalOutbound = 0;
            int outboundAllow = 0;
            int outboundBlock = 0;
            int anyAnyAllow = 0;

            // 1. Check default outbound action per profile
            ct.ThrowIfCancellationRequested();
            CheckDefaultOutbound(sb, evidence, ref hasIssue);

            // 2. Enumerate outbound rules
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Outbound Firewall Rules - active store (local, Group Policy and service rules)]");

            try
            {
                foreach (var rule in _readRules(ct, FirewallRuleReader.ActiveStore))
                {
                    ct.ThrowIfCancellationRequested();

                    if (!rule.IsOutbound) continue;

                    totalOutbound++;

                    if (rule.IsAllow)
                    {
                        outboundAllow++;

                        // A rule tied to one program, package, service or owner is application-aware egress, not any/any.
                        if (rule.HasAnyRemotePort && rule.HasAnyRemoteAddress && rule.HasNoApplicationScope)
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
                // Rule filters need elevation. netsh shows the local store only.
                evidence.AppendLine($"  WMI error: {ex.Message}");
                evidence.AppendLine("  netsh reads the local store only; Group Policy and service-added rules aren't included.");
                sb.AppendLine("NOTE: Rule filters couldn't be read (run elevated to include them), so the rule counts cover local rules only, not Group Policy or service-added ones.");
                localStoreOnly = true;
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
                sb.AppendLine($"WARNING: {anyAnyAllow} outbound ALLOW rules with no port, address or program restriction. " +
                    "Recommend implementing application-aware egress filtering.");
            }

            if (!hasIssue)
                sb.AppendLine(localStoreOnly
                    ? "Egress filtering appears configured among the local rules. Group Policy and service-added rules weren't checked, so this is Partial."
                    : "Egress filtering appears configured with outbound block rules.");

            // A local-only read can't clear the rules a Group Policy pushes.
            var status = hasIssue ? CheckStatus.Fail : localStoreOnly ? CheckStatus.Partial : CheckStatus.Pass;

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

    private void CheckDefaultOutbound(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("[Default Outbound Action per Profile]");

        foreach (var profile in _readOutboundDefaults())
        {
            string action = profile.Blocks switch
            {
                true => "Block",
                false => "Allow",
                null => "Unknown"
            };

            evidence.AppendLine($"  {profile.Profile}: DefaultOutboundAction = {action} ({profile.Source})");

            if (profile.Blocks == false)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {profile.Profile} default outbound action is ALLOW. " +
                    "Best practice is to set default outbound to BLOCK and whitelist required traffic.");
            }
            else if (profile.Blocks == true)
            {
                sb.AppendLine($"{profile.Profile}: Default outbound is BLOCK (good).");
            }
        }
    }

    /// <summary>
    /// Reads the enforced default outbound action from the active store (local and Group Policy
    /// settings merged), which any user can read. Falls back to the local policy in the registry.
    /// </summary>
    private static IReadOnlyList<OutboundDefault> ReadOutboundDefaults()
    {
        try
        {
            var profiles = new List<OutboundDefault>();
            using var searcher = FirewallRuleReader.CreateSearcher("SELECT Name, DefaultOutboundAction FROM MSFT_NetFirewallProfile", FirewallRuleReader.ActiveStore);
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                    profiles.Add(new OutboundDefault(obj["Name"]?.ToString() ?? "Unknown", BlocksOutbound(obj["DefaultOutboundAction"]), "active store"));
            }
            if (profiles.Count > 0)
                return profiles;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
        }

        string basePath = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        return [.. new[] { ("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile") }
            .Select(p =>
            {
                int value = RegistryHelper.GetValue<int>($@"{basePath}\{p.Item2}", "DefaultOutboundAction", -1);
                return new OutboundDefault(p.Item1, value switch { 0 => false, 1 => true, _ => null }, "local policy in the registry");
            })];
    }

    /// <summary>MSFT_NetFirewallProfile actions: 2 Allow, 4 Block; 0 (not configured) means the Windows default, Allow.</summary>
    internal static bool? BlocksOutbound(object? value)
    {
        if (value is null) return null;
        try
        {
            return Convert.ToUInt16(value, CultureInfo.InvariantCulture) switch
            {
                4 => true,
                0 or 2 => false,
                _ => null
            };
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private void QueryOutboundViaNetsh(
        StringBuilder evidence,
        ref int totalOutbound,
        ref int outboundAllow,
        ref int outboundBlock,
        ref int anyAnyAllow,
        CancellationToken ct)
    {
        try
        {
            string output = _runCommand("netsh", "advfirewall firewall show rule name=all dir=out verbose", ct);

            evidence.AppendLine("  [Parsed from netsh output]");

            string currentName = "";
            bool currentEnabled = false;
            string currentAction = "";
            string currentRemotePort = "";
            string currentRemoteAddr = "";
            string currentProgram = "";
            string currentService = "";

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    ProcessNetshOutboundRule(evidence, ref totalOutbound, ref outboundAllow, ref outboundBlock,
                        ref anyAnyAllow, currentName, currentEnabled, currentAction, currentRemotePort, currentRemoteAddr,
                        currentProgram, currentService);

                    currentName = line[10..].Trim();
                    currentEnabled = false;
                    currentAction = "";
                    currentRemotePort = "";
                    currentRemoteAddr = "";
                    currentProgram = "";
                    currentService = "";
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
                else if (line.StartsWith("Program:", StringComparison.OrdinalIgnoreCase))
                {
                    currentProgram = line[8..].Trim();
                }
                else if (line.StartsWith("Service:", StringComparison.OrdinalIgnoreCase))
                {
                    currentService = line[8..].Trim();
                }
            }

            ProcessNetshOutboundRule(evidence, ref totalOutbound, ref outboundAllow, ref outboundBlock,
                ref anyAnyAllow, currentName, currentEnabled, currentAction, currentRemotePort, currentRemoteAddr,
                currentProgram, currentService);
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
        string remoteAddr,
        string program,
        string service)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalOutbound++;

        if (action.Contains("Allow", StringComparison.OrdinalIgnoreCase))
        {
            outboundAllow++;

            if (FirewallRuleReader.IsAnyValue([remotePort]) && FirewallRuleReader.IsAnyValue([remoteAddr]) &&
                FirewallRuleReader.IsUnscoped(program) && FirewallRuleReader.IsUnscoped(service))
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

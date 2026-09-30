namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP01 - Firewall rule analysis: count inbound allow rules, find any/any rules with no port
///        restriction, remote address = Any and no program, package, service or owner scope.
///        Rules come from the active store, so Group Policy and service-added rules count.
/// </summary>
public sealed class NP01_FirewallRulesCheck : ISecurityCheck
{
    private readonly Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>> _readRules;
    private readonly Func<string, string, CancellationToken, string> _runCommand;

    public string Id => "NP01";

    public NP01_FirewallRulesCheck()
        : this(null, null)
    {
    }

    internal NP01_FirewallRulesCheck(
        Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>>? readRules,
        Func<string, string, CancellationToken, string>? runCommand = null)
    {
        _readRules = readRules ?? ((ct, store) => FirewallRuleReader.GetEnabledRules(ct, store));
        _runCommand = runCommand ?? ((file, args, ct) => CommandRunner.RunForOutput(file, args, TimeSpan.FromSeconds(30), ct));
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            evidence.AppendLine("[Windows Firewall Rules Analysis - active store (local, Group Policy and service rules)]");

            ct.ThrowIfCancellationRequested();

            int totalInbound = 0;
            int inboundAllow = 0;
            int anyAnyRules = 0;
            var anyAnyNames = new List<string>();

            try
            {
                foreach (var rule in _readRules(ct, FirewallRuleReader.ActiveStore))
                {
                    ct.ThrowIfCancellationRequested();

                    if (!rule.IsInbound) continue;

                    totalInbound++;

                    if (!rule.IsAllow) continue;

                    inboundAllow++;

                    // A program-, package-, service- or owner-scoped rule only opens ports to that one thing.
                    if (rule.HasAnyLocalPort && rule.HasAnyRemoteAddress && rule.HasNoApplicationScope)
                    {
                        anyAnyRules++;
                        anyAnyNames.Add(rule.Name);
                        evidence.AppendLine($"  ANY/ANY ALLOW: {rule.Name} (Protocol={rule.Protocol ?? "Any"}, " +
                            $"LocalPort={FirewallRuleReader.FormatValues(rule.LocalPorts)}, " +
                            $"RemoteAddr={FirewallRuleReader.FormatValues(rule.RemoteAddresses)})");
                    }
                }
            }
            catch (ManagementException ex)
            {
                // Rule filters need elevation. netsh shows the local store only.
                ct.ThrowIfCancellationRequested();
                evidence.AppendLine($"  WMI error: {ex.Message}");
                evidence.AppendLine("  netsh reads the local store only; Group Policy and service-added rules aren't included.");
                sb.AppendLine("NOTE: Rule filters couldn't be read (run elevated to include them), so this covers local rules only, not Group Policy or service-added ones.");
                QueryViaNetsh(sb, evidence, ref totalInbound, ref inboundAllow, ref anyAnyRules, anyAnyNames, ct);
            }

            evidence.AppendLine($"\n  Summary: {totalInbound} enabled inbound rules, {inboundAllow} allow, {anyAnyRules} any/any allow");

            sb.AppendLine($"Inbound firewall rules: {totalInbound} total, {inboundAllow} allow rules.");

            if (anyAnyRules > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {anyAnyRules} inbound ALLOW rule(s) have no port or remote address restriction (any/any):");
                foreach (var name in anyAnyNames.Take(10))
                    sb.AppendLine($"  - {name}");
                if (anyAnyNames.Count > 10)
                    sb.AppendLine($"  ... and {anyAnyNames.Count - 10} more.");
            }

            if (inboundAllow > 50)
            {
                sb.AppendLine($"WARNING: {inboundAllow} inbound allow rules is a large attack surface. Review for stale/unnecessary rules.");
            }

            if (!hasIssue)
                sb.AppendLine("PASS: No unrestricted (any/any) inbound allow rules detected.");

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

    private void QueryViaNetsh(
        StringBuilder sb, StringBuilder evidence,
        ref int totalInbound, ref int inboundAllow, ref int anyAnyRules,
        List<string> anyAnyNames, CancellationToken ct)
    {
        try
        {
            string output = _runCommand("netsh", "advfirewall firewall show rule name=all dir=in verbose", ct);

            evidence.AppendLine("\n  [Parsed from netsh output]");

            // Parse netsh output into rule blocks. Verbose output adds Program and Service lines.
            string currentName = "";
            bool currentEnabled = false;
            string currentAction = "";
            string currentLocalPort = "";
            string currentRemoteAddr = "";
            string currentProgram = "";
            string currentService = "";

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    // Process previous rule
                    ProcessNetshRule(ref totalInbound, ref inboundAllow, ref anyAnyRules,
                        anyAnyNames, currentName, currentEnabled, currentAction, currentLocalPort, currentRemoteAddr,
                        currentProgram, currentService);

                    currentName = line[10..].Trim();
                    currentEnabled = false;
                    currentAction = "";
                    currentLocalPort = "";
                    currentRemoteAddr = "";
                    currentProgram = "";
                    currentService = "";
                }
                else if (line.StartsWith("Program:", StringComparison.OrdinalIgnoreCase))
                {
                    currentProgram = line[8..].Trim();
                }
                else if (line.StartsWith("Service:", StringComparison.OrdinalIgnoreCase))
                {
                    currentService = line[8..].Trim();
                }
                else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                {
                    currentEnabled = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                }
                else if (line.StartsWith("Action:", StringComparison.OrdinalIgnoreCase))
                {
                    currentAction = line[7..].Trim();
                }
                else if (line.StartsWith("LocalPort:", StringComparison.OrdinalIgnoreCase))
                {
                    currentLocalPort = line[10..].Trim();
                }
                else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
                {
                    currentRemoteAddr = line[9..].Trim();
                }
            }

            // Process last rule
            ProcessNetshRule(ref totalInbound, ref inboundAllow, ref anyAnyRules,
                anyAnyNames, currentName, currentEnabled, currentAction, currentLocalPort, currentRemoteAddr,
                currentProgram, currentService);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh fallback error: {ex.Message}");
        }
    }

    private static void ProcessNetshRule(
        ref int totalInbound, ref int inboundAllow, ref int anyAnyRules,
        List<string> anyAnyNames,
        string name, bool enabled, string action, string localPort, string remoteAddr,
        string program, string service)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalInbound++;

        if (!action.Contains("Allow", StringComparison.OrdinalIgnoreCase)) return;

        inboundAllow++;

        bool isAnyPort = string.IsNullOrEmpty(localPort) || localPort == "Any";
        bool isAnyRemote = string.IsNullOrEmpty(remoteAddr) || remoteAddr == "Any";
        bool isUnscoped = FirewallRuleReader.IsUnscoped(program) && FirewallRuleReader.IsUnscoped(service);

        if (isAnyPort && isAnyRemote && isUnscoped)
        {
            anyAnyRules++;
            anyAnyNames.Add(name);
        }
    }
}

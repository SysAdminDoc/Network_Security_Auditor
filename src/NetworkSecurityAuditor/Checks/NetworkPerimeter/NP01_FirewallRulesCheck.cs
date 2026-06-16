namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP01 - Firewall rule analysis: count inbound allow rules, find any/any rules
///        with no port restriction and remote address = Any.
/// </summary>
public sealed class NP01_FirewallRulesCheck : ISecurityCheck
{
    public string Id => "NP01";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            evidence.AppendLine("[Windows Firewall Rules Analysis]");

            ct.ThrowIfCancellationRequested();

            int totalInbound = 0;
            int inboundAllow = 0;
            int anyAnyRules = 0;
            var anyAnyNames = new List<string>();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\StandardCimv2",
                    "SELECT InstanceID, ElementName, Direction, Action, " +
                    "LocalPort, RemoteAddress, Protocol, Enabled " +
                    "FROM MSFT_NetFirewallRule WHERE Enabled = 1");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();

                    int direction = Convert.ToInt32(obj["Direction"] ?? 0);
                    int action = Convert.ToInt32(obj["Action"] ?? 0);

                    // Direction: 1=Inbound, 2=Outbound
                    if (direction != 1) continue;

                    totalInbound++;

                    // Action: 2=Allow, 4=Block
                    if (action != 2) continue;

                    inboundAllow++;

                    // Check for overly permissive rules
                    string name = obj["ElementName"]?.ToString() ?? obj["InstanceID"]?.ToString() ?? "Unknown";
                    string? localPort = obj["LocalPort"]?.ToString();
                    string? remoteAddr = obj["RemoteAddress"]?.ToString();
                    string? protocol = obj["Protocol"]?.ToString();

                    bool isAnyPort = string.IsNullOrEmpty(localPort) || localPort == "Any" || localPort == "*";
                    bool isAnyRemote = string.IsNullOrEmpty(remoteAddr) || remoteAddr == "Any" || remoteAddr == "*"
                                    || remoteAddr == "LocalSubnet" == false; // Not restricted to local

                    // Check if truly any/any (no port restriction AND no remote restriction)
                    if (isAnyPort && (string.IsNullOrEmpty(remoteAddr) || remoteAddr == "Any" || remoteAddr == "*"))
                    {
                        anyAnyRules++;
                        anyAnyNames.Add(name);
                        evidence.AppendLine($"  ANY/ANY ALLOW: {name} (Protocol={protocol ?? "Any"}, " +
                            $"LocalPort={localPort ?? "Any"}, RemoteAddr={remoteAddr ?? "Any"})");
                    }
                }
            }
            catch (ManagementException)
            {
                // Fallback: use netsh parsing
                ct.ThrowIfCancellationRequested();
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

    private static void QueryViaNetsh(
        StringBuilder sb, StringBuilder evidence,
        ref int totalInbound, ref int inboundAllow, ref int anyAnyRules,
        List<string> anyAnyNames, CancellationToken ct)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("netsh", "advfirewall firewall show rule name=all dir=in")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null) return;

            ct.Register(() => { try { proc.Kill(); } catch { } });

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(30_000);

            evidence.AppendLine("\n  [Parsed from netsh output]");

            // Parse netsh output into rule blocks
            string currentName = "";
            bool currentEnabled = false;
            string currentAction = "";
            string currentLocalPort = "";
            string currentRemoteAddr = "";

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    // Process previous rule
                    ProcessNetshRule(ref totalInbound, ref inboundAllow, ref anyAnyRules,
                        anyAnyNames, currentName, currentEnabled, currentAction, currentLocalPort, currentRemoteAddr);

                    currentName = line[10..].Trim();
                    currentEnabled = false;
                    currentAction = "";
                    currentLocalPort = "";
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
                anyAnyNames, currentName, currentEnabled, currentAction, currentLocalPort, currentRemoteAddr);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh fallback error: {ex.Message}");
        }
    }

    private static void ProcessNetshRule(
        ref int totalInbound, ref int inboundAllow, ref int anyAnyRules,
        List<string> anyAnyNames,
        string name, bool enabled, string action, string localPort, string remoteAddr)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalInbound++;

        if (!action.Contains("Allow", StringComparison.OrdinalIgnoreCase)) return;

        inboundAllow++;

        bool isAnyPort = string.IsNullOrEmpty(localPort) || localPort == "Any";
        bool isAnyRemote = string.IsNullOrEmpty(remoteAddr) || remoteAddr == "Any";

        if (isAnyPort && isAnyRemote)
        {
            anyAnyRules++;
            anyAnyNames.Add(name);
        }
    }
}

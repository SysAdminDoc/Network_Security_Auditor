namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP06 - Temporary Firewall Rules: Check firewall rules for stale/temporary indicators --
/// rules with "temp", "test", "old" in names, or very old creation dates.
/// </summary>
public sealed class NP06_TempRulesCheck : ISecurityCheck
{
    public string Id => "NP06";

    private static readonly string[] StaleIndicators =
    [
        "temp", "test", "old", "delete", "remove", "tmp", "debug",
        "deprecated", "disable", "unused", "backup", "copy of", "trial"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            var staleRules = new List<string>();
            int totalRules = 0;

            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Firewall Rule Staleness Analysis]");

            try
            {
                foreach (var rule in FirewallRuleReader.GetEnabledRules(ct))
                {
                    ct.ThrowIfCancellationRequested();
                    totalRules++;

                    string name = rule.Name;
                    string desc = rule.Description;

                    ProcessRuleForStaleness(evidence, staleRules, name, desc);
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
                QueryViaNetsh(evidence, staleRules, ref totalRules, ct);
            }

            evidence.AppendLine($"\n  Total enabled rules: {totalRules}");
            evidence.AppendLine($"  Rules with stale indicators: {staleRules.Count}");

            sb.AppendLine($"Scanned {totalRules} enabled firewall rules for staleness indicators.");

            if (staleRules.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"\nWARNING: {staleRules.Count} firewall rule(s) have stale/temporary indicators:");
                foreach (string rule in staleRules.Take(20))
                    sb.AppendLine($"  - {rule}");
                if (staleRules.Count > 20)
                    sb.AppendLine($"  ... and {staleRules.Count - 20} more.");

                sb.AppendLine("\nRecommendation: Review and remove temporary/test firewall rules. " +
                    "Stale rules can create unintended access paths or policy drift.");
            }
            else
            {
                sb.AppendLine("PASS: No rules with obvious stale/temporary naming detected.");
            }

            var status = hasIssue ? CheckStatus.Partial : CheckStatus.Pass;

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

    private static bool HasDatePattern(string name)
    {
        // Check for common date patterns: YYYY-MM-DD, MM/DD/YYYY, YYYYMMDD
        if (string.IsNullOrEmpty(name)) return false;

        // Look for 4-digit years followed by separators and digits
        for (int i = 0; i <= name.Length - 10; i++)
        {
            if (char.IsDigit(name[i]) && char.IsDigit(name[i + 1]) &&
                char.IsDigit(name[i + 2]) && char.IsDigit(name[i + 3]))
            {
                int year = int.Parse(name.AsSpan(i, 4));
                if (year is >= 2015 and <= 2030)
                {
                    // Check if followed by separator and more digits
                    if (i + 4 < name.Length && (name[i + 4] is '-' or '/' or '.'))
                        return true;
                }
            }
        }

        return false;
    }

    private static void QueryViaNetsh(
        StringBuilder evidence,
        List<string> staleRules,
        ref int totalRules,
        CancellationToken ct)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("netsh", "advfirewall firewall show rule name=all")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null) return;

            using var registration = ct.Register(() => { try { proc.Kill(); } catch { } });
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(30_000);

            evidence.AppendLine("  [Parsed from netsh output]");

            string currentName = "";
            string currentDescription = "";
            bool currentEnabled = false;

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    ProcessNetshRule(evidence, staleRules, ref totalRules, currentName, currentDescription, currentEnabled);

                    currentName = line[10..].Trim();
                    currentDescription = "";
                    currentEnabled = false;
                }
                else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                {
                    currentEnabled = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                }
                else if (line.StartsWith("Description:", StringComparison.OrdinalIgnoreCase))
                {
                    currentDescription = line[12..].Trim();
                }
            }

            ProcessNetshRule(evidence, staleRules, ref totalRules, currentName, currentDescription, currentEnabled);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh fallback error: {ex.Message}");
        }
    }

    private static void ProcessNetshRule(
        StringBuilder evidence,
        List<string> staleRules,
        ref int totalRules,
        string name,
        string description,
        bool enabled)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalRules++;
        ProcessRuleForStaleness(evidence, staleRules, name, description);
    }

    private static void ProcessRuleForStaleness(
        StringBuilder evidence,
        List<string> staleRules,
        string name,
        string desc)
    {
        foreach (string indicator in StaleIndicators)
        {
            if (name.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                desc.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                staleRules.Add(name);
                evidence.AppendLine($"  STALE INDICATOR: \"{name}\" (matched: \"{indicator}\")");
                if (!string.IsNullOrEmpty(desc))
                    evidence.AppendLine($"    Description: {desc}");
                break;
            }
        }

        if (HasDatePattern(name) && !staleRules.Contains(name))
        {
            staleRules.Add(name);
            evidence.AppendLine($"  DATE IN NAME: \"{name}\" (may be a temporary rule)");
        }
    }
}

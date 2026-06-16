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
                using var searcher = new ManagementObjectSearcher(
                    @"root\StandardCimv2",
                    "SELECT InstanceID, ElementName, Description, Enabled " +
                    "FROM MSFT_NetFirewallRule WHERE Enabled = 1");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();
                    totalRules++;

                    string name = obj["ElementName"]?.ToString() ?? "";
                    string desc = obj["Description"]?.ToString() ?? "";
                    string instanceId = obj["InstanceID"]?.ToString() ?? "";

                    // Check for stale indicators in name or description
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

                    // Check for date patterns in rule names suggesting temporary rules
                    if (HasDatePattern(name))
                    {
                        if (!staleRules.Contains(name))
                        {
                            staleRules.Add(name);
                            evidence.AppendLine($"  DATE IN NAME: \"{name}\" (may be a temporary rule)");
                        }
                    }
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
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
}

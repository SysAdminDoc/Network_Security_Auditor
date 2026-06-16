namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// LM05 - Failed logon analysis: event 4625 in the last 7 days, grouped by username.
/// </summary>
public sealed class LM05_FailedLogonCheck : ISecurityCheck
{
    public string Id => "LM05";

    private const int LookbackDays = 7;
    private const int BruteForceThreshold = 50;
    private const int WarningThreshold = 10;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            evidence.AppendLine($"[Failed Logon Events - Last {LookbackDays} Days]");

            if (!env.IsAdmin)
            {
                sb.AppendLine("Security event log requires administrator privileges to read.");
                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.NA,
                    Findings = sb.ToString().TrimEnd(),
                    Evidence = "Requires elevation to read Security event log."
                });
            }

            ct.ThrowIfCancellationRequested();

            var failedLogons = QueryFailedLogons(evidence, ct);

            evidence.AppendLine($"\n  Total 4625 events: {failedLogons.Values.Sum()}");

            if (failedLogons.Count == 0)
            {
                sb.AppendLine("No failed logon events (4625) found in the last 7 days.");
                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.Pass,
                    Findings = sb.ToString().TrimEnd(),
                    Evidence = evidence.ToString().TrimEnd()
                });
            }

            // Sort by count descending
            var sorted = failedLogons
                .OrderByDescending(kv => kv.Value)
                .ToList();

            sb.AppendLine($"Found {failedLogons.Values.Sum()} failed logon events across {failedLogons.Count} account(s) in last {LookbackDays} days.");
            sb.AppendLine();
            sb.AppendLine("Top accounts by failed logon count:");

            int shown = 0;
            foreach (var (account, count) in sorted)
            {
                if (shown >= 15) break; // Limit output
                string flag = count >= BruteForceThreshold ? " [BRUTE FORCE SUSPECT]"
                    : count >= WarningThreshold ? " [ELEVATED]"
                    : "";
                sb.AppendLine($"  {account}: {count}{flag}");
                shown++;
            }

            // Determine severity
            int maxCount = sorted[0].Value;
            if (maxCount >= BruteForceThreshold)
            {
                hasIssue = true;
                sb.AppendLine();
                sb.AppendLine($"CRITICAL: Account '{sorted[0].Key}' has {maxCount} failed logons - possible brute force attack.");
            }
            else if (maxCount >= WarningThreshold)
            {
                sb.AppendLine();
                sb.AppendLine($"WARNING: Elevated failed logon activity detected (max {maxCount} for '{sorted[0].Key}').");
            }

            // Check for common attack patterns
            CheckAttackPatterns(sorted, sb, ref hasIssue);

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

    private static Dictionary<string, int> QueryFailedLogons(StringBuilder evidence, CancellationToken ct)
    {
        var results = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var startTime = DateTime.UtcNow.AddDays(-LookbackDays);

            // Use EventLog reader
            var log = new EventLog("Security");
            int totalEntries = log.Entries.Count;
            evidence.AppendLine($"  Security log entries: {totalEntries}");

            // Read backwards for efficiency (newest first)
            for (int i = totalEntries - 1; i >= 0; i--)
            {
                ct.ThrowIfCancellationRequested();

                EventLogEntry entry;
                try
                {
                    entry = log.Entries[i];
                }
                catch
                {
                    continue; // Entry may have been purged
                }

                // Stop if we've gone past the lookback window
                if (entry.TimeGenerated.ToUniversalTime() < startTime)
                    break;

                if (entry.InstanceId != 4625) continue;

                // Extract target username from the event message
                // ReplacementStrings[5] = TargetUserName in 4625 events
                string account = "Unknown";
                try
                {
                    if (entry.ReplacementStrings.Length > 6)
                    {
                        string domain = entry.ReplacementStrings[6]; // TargetDomainName
                        string user = entry.ReplacementStrings[5]; // TargetUserName
                        account = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                    }
                }
                catch
                {
                    // Malformed event
                }

                if (string.IsNullOrWhiteSpace(account) || account == "-" || account == @"\")
                    continue;

                results.TryGetValue(account, out int existing);
                results[account] = existing + 1;
            }

            log.Dispose();
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error reading Security log: {ex.Message}");
        }

        return results;
    }

    private static void CheckAttackPatterns(
        List<KeyValuePair<string, int>> sorted,
        StringBuilder sb,
        ref bool hasIssue)
    {
        // Password spraying indicator: many accounts with similar low failure counts
        int accountsWithFiveOrMore = sorted.Count(kv => kv.Value >= 5);
        if (accountsWithFiveOrMore >= 10)
        {
            hasIssue = true;
            sb.AppendLine($"WARNING: {accountsWithFiveOrMore} accounts have 5+ failures - possible password spray attack.");
        }

        // Well-known target accounts
        var sensitiveAccounts = new[] { "administrator", "admin", "sa", "root", "guest" };
        foreach (var (account, count) in sorted)
        {
            string lower = account.Split('\\').Last().ToLowerInvariant();
            if (sensitiveAccounts.Contains(lower) && count >= 5)
            {
                sb.AppendLine($"WARNING: Sensitive account '{account}' has {count} failed logons.");
            }
        }
    }
}

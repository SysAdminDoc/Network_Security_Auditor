namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// BR03 - Restore Testing: Interview-required. Check for recent backup job completions
/// via event logs (Backup events).
/// </summary>
public sealed class BR03_RestoreTestCheck : ISecurityCheck
{
    public string Id => "BR03";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasRecentBackup = false;

            // 1. Check Windows Backup event log
            ct.ThrowIfCancellationRequested();
            CheckBackupEventLog(sb, evidence, ref hasRecentBackup);

            // 2. Check Application event log for backup-related events
            ct.ThrowIfCancellationRequested();
            CheckApplicationBackupEvents(sb, evidence, ref hasRecentBackup);

            // Summary and interview items
            if (hasRecentBackup)
            {
                sb.Insert(0, "Recent backup activity detected in event logs.\n");
            }
            else
            {
                sb.Insert(0, "No recent backup events found in Windows event logs.\n");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Restore Testing Review:");
            sb.AppendLine("  [ ] Restore tests are performed regularly (at least quarterly)");
            sb.AppendLine("  [ ] Last restore test date and result documented");
            sb.AppendLine("  [ ] Full system restore has been tested (not just file-level)");
            sb.AppendLine("  [ ] Restore times are measured and meet RTO targets");
            sb.AppendLine("  [ ] Restored data integrity is verified");
            sb.AppendLine("  [ ] Restore procedure is documented and accessible offline");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview backup administrator " +
                "for restore test results and frequency.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void CheckBackupEventLog(StringBuilder sb, StringBuilder evidence,
        ref bool hasRecentBackup)
    {
        evidence.AppendLine("[Windows Backup Event Log]");

        try
        {
            // Check Microsoft-Windows-Backup event log
            using var log = new EventLog("Microsoft-Windows-Backup");

            var recentEntries = log.Entries.Cast<EventLogEntry>()
                .Where(e => e.TimeGenerated >= DateTime.Now.AddDays(-30))
                .OrderByDescending(e => e.TimeGenerated)
                .Take(10)
                .ToList();

            if (recentEntries.Count > 0)
            {
                hasRecentBackup = true;
                evidence.AppendLine($"  Recent backup events (last 30 days): {recentEntries.Count}");

                foreach (var entry in recentEntries.Take(5))
                {
                    evidence.AppendLine($"    {entry.TimeGenerated:yyyy-MM-dd HH:mm} " +
                        $"[{entry.EntryType}] EventID={entry.EventID}: " +
                        $"{Truncate(entry.Message, 100)}");
                }

                sb.AppendLine($"Windows Backup events found: {recentEntries.Count} in last 30 days.");
            }
            else
            {
                evidence.AppendLine("  No backup events in last 30 days.");
            }
        }
        catch (Exception)
        {
            evidence.AppendLine("  Microsoft-Windows-Backup event log not accessible.");
        }
    }

    private static void CheckApplicationBackupEvents(StringBuilder sb, StringBuilder evidence,
        ref bool hasRecentBackup)
    {
        evidence.AppendLine("\n[Application Log - Backup Events]");

        try
        {
            using var log = new EventLog("Application");

            string[] backupSources =
            [
                "Veeam", "Acronis", "Windows Server Backup",
                "wbengine", "Datto", "Commvault", "Backup Exec"
            ];

            var recentBackupEntries = log.Entries.Cast<EventLogEntry>()
                .Where(e => e.TimeGenerated >= DateTime.Now.AddDays(-30))
                .Where(e => backupSources.Any(src =>
                    (e.Source ?? "").Contains(src, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(e => e.TimeGenerated)
                .Take(10)
                .ToList();

            if (recentBackupEntries.Count > 0)
            {
                hasRecentBackup = true;
                evidence.AppendLine($"  Backup-related application events (last 30 days): {recentBackupEntries.Count}");

                foreach (var entry in recentBackupEntries.Take(5))
                {
                    evidence.AppendLine($"    {entry.TimeGenerated:yyyy-MM-dd HH:mm} " +
                        $"[{entry.Source}] {entry.EntryType}: {Truncate(entry.Message, 80)}");
                }
            }
            else
            {
                evidence.AppendLine("  No backup-related events found in Application log.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error reading Application log: {ex.Message}");
        }
    }

    private static string Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return "(empty)";
        string clean = value.Replace('\n', ' ').Replace('\r', ' ');
        return clean.Length <= maxLength ? clean : clean[..maxLength] + "...";
    }
}

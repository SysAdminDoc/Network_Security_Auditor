namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// BR06 - Backup Monitoring: Check for backup monitoring alerts. Check backup service
/// event logs for recent failures.
/// </summary>
public sealed class BR06_BackupMonitoringCheck : ISecurityCheck
{
    public string Id => "BR06";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasFailures = false;
            bool hasRecentActivity = false;

            // 1. Check for backup failure events in Application log
            ct.ThrowIfCancellationRequested();
            CheckBackupFailureEvents(sb, evidence, ref hasFailures, ref hasRecentActivity);

            // 2. Check System log for VSS errors
            ct.ThrowIfCancellationRequested();
            CheckVssErrors(sb, evidence, ref hasFailures);

            // 3. Check for monitoring agent services
            ct.ThrowIfCancellationRequested();
            CheckMonitoringAgents(sb, evidence);

            // Summary
            if (hasFailures)
            {
                sb.Insert(0, "Backup failures detected in event logs.\n");
            }
            else if (hasRecentActivity)
            {
                sb.Insert(0, "Backup activity detected with no recent failures.\n");
            }
            else
            {
                sb.Insert(0, "No backup monitoring events found.\n");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Backup Monitoring:");
            sb.AppendLine("  [ ] Backup job success/failure alerts are configured");
            sb.AppendLine("  [ ] Failed backup alerts go to monitored inbox/dashboard");
            sb.AppendLine("  [ ] Backup monitoring is reviewed daily");
            sb.AppendLine("  [ ] Backup size/duration trends are tracked");
            sb.AppendLine("  [ ] Alert escalation procedures exist for persistent failures");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Verify backup monitoring " +
                "dashboards and alert configurations with backup administrator.");

            var status = hasFailures ? CheckStatus.Fail : CheckStatus.Partial;

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

    private static void CheckBackupFailureEvents(StringBuilder sb, StringBuilder evidence,
        ref bool hasFailures, ref bool hasRecentActivity)
    {
        evidence.AppendLine("[Backup Events - Application Log]");

        try
        {
            using var log = new EventLog("Application");

            var cutoff = DateTime.Now.AddDays(-7);

            string[] backupSources =
            [
                "Veeam", "Acronis", "Windows Backup", "wbengine",
                "Datto", "Commvault", "Backup Exec", "Volume Shadow Copy",
                "Microsoft-Windows-Backup"
            ];

            int errorCount = 0;
            int warningCount = 0;
            int infoCount = 0;

            foreach (EventLogEntry entry in log.Entries)
            {
                if (entry.TimeGenerated < cutoff) continue;

                string source = entry.Source ?? "";
                if (!backupSources.Any(s => source.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    continue;

                hasRecentActivity = true;

                switch (entry.EntryType)
                {
                    case EventLogEntryType.Error:
                        errorCount++;
                        if (errorCount <= 5)
                        {
                            evidence.AppendLine($"  ERROR: {entry.TimeGenerated:yyyy-MM-dd HH:mm} " +
                                $"[{source}] {Truncate(entry.Message, 100)}");
                        }
                        break;
                    case EventLogEntryType.Warning:
                        warningCount++;
                        break;
                    default:
                        infoCount++;
                        break;
                }
            }

            evidence.AppendLine($"\n  Last 7 days: {errorCount} errors, {warningCount} warnings, {infoCount} info");

            if (errorCount > 0)
            {
                hasFailures = true;
                sb.AppendLine($"WARNING: {errorCount} backup error event(s) in the last 7 days. " +
                    "Investigate and resolve failed backups immediately.");
            }
            else if (warningCount > 0)
            {
                sb.AppendLine($"INFO: {warningCount} backup warning(s) in the last 7 days.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error reading event log: {ex.Message}");
        }
    }

    private static void CheckVssErrors(StringBuilder sb, StringBuilder evidence, ref bool hasFailures)
    {
        evidence.AppendLine("\n[VSS Errors - System Log]");

        try
        {
            using var log = new EventLog("System");

            var cutoff = DateTime.Now.AddDays(-7);
            int vssErrors = 0;

            foreach (EventLogEntry entry in log.Entries)
            {
                if (entry.TimeGenerated < cutoff) continue;
                if (entry.EntryType != EventLogEntryType.Error) continue;

                string source = entry.Source ?? "";
                if (source.Contains("VSS", StringComparison.OrdinalIgnoreCase) ||
                    source.Contains("Volume Shadow", StringComparison.OrdinalIgnoreCase) ||
                    source.Contains("volsnap", StringComparison.OrdinalIgnoreCase))
                {
                    vssErrors++;
                    if (vssErrors <= 3)
                    {
                        evidence.AppendLine($"  {entry.TimeGenerated:yyyy-MM-dd HH:mm} " +
                            $"[{source}] {Truncate(entry.Message, 100)}");
                    }
                }
            }

            if (vssErrors > 0)
            {
                hasFailures = true;
                sb.AppendLine($"WARNING: {vssErrors} VSS error(s) in the last 7 days. " +
                    "VSS failures can prevent backups from completing.");
            }

            evidence.AppendLine($"  VSS errors in last 7 days: {vssErrors}");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error reading System log: {ex.Message}");
        }
    }

    private static void CheckMonitoringAgents(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[Monitoring Agent Check]");

        var monitoringKeys = new Dictionary<string, string>
        {
            { @"HKLM\SOFTWARE\ConnectWise", "ConnectWise Automate" },
            { @"HKLM\SOFTWARE\Datto\RMM", "Datto RMM" },
            { @"HKLM\SOFTWARE\NinjaRMM", "NinjaRMM" },
            { @"HKLM\SOFTWARE\N-able", "N-able" },
            { @"HKLM\SOFTWARE\Kaseya", "Kaseya" },
            { @"HKLM\SOFTWARE\Zabbix Agent", "Zabbix" },
            { @"HKLM\SOFTWARE\PRTG", "PRTG" },
        };

        foreach (var (path, label) in monitoringKeys)
        {
            if (Services.RegistryHelper.KeyExists(path))
            {
                evidence.AppendLine($"  FOUND: {label}");
                sb.AppendLine($"RMM/Monitoring agent detected: {label} (may include backup monitoring).");
            }
        }
    }

    private static string Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return "(empty)";
        string clean = value.Replace('\n', ' ').Replace('\r', ' ');
        return clean.Length <= maxLength ? clean : clean[..maxLength] + "...";
    }
}

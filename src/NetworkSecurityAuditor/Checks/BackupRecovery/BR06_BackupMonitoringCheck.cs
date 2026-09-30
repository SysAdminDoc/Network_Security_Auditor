namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// BR06 - Backup Monitoring: Check for backup monitoring alerts. Check backup service
/// event logs for recent failures.
/// </summary>
public sealed class BR06_BackupMonitoringCheck : ISecurityCheck
{
    public string Id => "BR06";

    private const int ErrorSampleCount = 5;
    private const int VssSampleCount = 3;

    private static readonly string[] BackupSources =
    [
        "Veeam", "Acronis", "Windows Backup", "wbengine",
        "Datto", "Commvault", "Backup Exec", "Volume Shadow Copy",
        "Microsoft-Windows-Backup"
    ];

    private readonly IEventLogReader _events;

    public BR06_BackupMonitoringCheck() : this(SystemEventLogReader.Instance) { }

    internal BR06_BackupMonitoringCheck(IEventLogReader events) => _events = events;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasFailures = false;
            bool hasRecentActivity = false;
            bool errorsIncomplete = false;
            bool activityIncomplete = false;

            // 1. Check for backup failure events in Application log
            ct.ThrowIfCancellationRequested();
            CheckBackupFailureEvents(sb, evidence, ref hasFailures, ref hasRecentActivity,
                ref errorsIncomplete, ref activityIncomplete, ct);

            // 2. Check System log for VSS errors
            ct.ThrowIfCancellationRequested();
            CheckVssErrors(sb, evidence, ref hasFailures, ct);

            // 3. Check for monitoring agent services
            ct.ThrowIfCancellationRequested();
            CheckMonitoringAgents(sb, evidence);

            // Summary
            if (hasFailures)
            {
                sb.Insert(0, "Backup failures detected in event logs.\n");
            }
            else if (errorsIncomplete)
            {
                sb.Insert(0, "Backup failures couldn't be ruled out: the Application log held more error events than one read covers.\n");
            }
            else if (hasRecentActivity)
            {
                sb.Insert(0, "Backup activity detected with no recent failures.\n");
            }
            else if (activityIncomplete)
            {
                sb.Insert(0, "No backup events among the events read. The Application log held more events than one read covers, so older backup events weren't checked.\n");
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

    private void CheckBackupFailureEvents(StringBuilder sb, StringBuilder evidence,
        ref bool hasFailures, ref bool hasRecentActivity,
        ref bool errorsIncomplete, ref bool activityIncomplete, CancellationToken ct)
    {
        evidence.AppendLine("[Backup Events - Application Log]");

        try
        {
            int errorCount = 0;
            int warningCount = 0;
            int infoCount = 0;

            // Provider names are matched by substring, which the event log's XPath can't express, so the
            // time window and level are filtered at the source and the provider match happens here, under the
            // read cap. Errors get a read of their own, so a busy log's routine events can't push older backup
            // errors past the cap. Only the error samples shown below get a rendered message.
            int errorsSampled = 0;
            var errors = _events.Query("Application",
                EventLogQueryHelper.RecentEventsQuery(TimeSpan.FromDays(7), "Level=2"),
                EventLogQueryHelper.MaxEventsPerQuery,
                formatMessage: e => IsBackupSource(e.ProviderName) && errorsSampled++ < ErrorSampleCount, ct);
            foreach (var entry in errors.Records.Where(e => IsBackupSource(e.ProviderName)))
            {
                hasRecentActivity = true;
                errorCount++;
                if (errorCount <= ErrorSampleCount)
                {
                    evidence.AppendLine($"  ERROR: {entry.TimeCreated:yyyy-MM-dd HH:mm} " +
                        $"[{entry.ProviderName}] {Truncate(entry.Message, 100)}");
                }
            }

            ct.ThrowIfCancellationRequested();
            var others = _events.Query("Application",
                EventLogQueryHelper.RecentEventsQuery(TimeSpan.FromDays(7), "Level!=2"),
                EventLogQueryHelper.MaxEventsPerQuery, formatMessage: null, ct);
            foreach (var entry in others.Records.Where(e => IsBackupSource(e.ProviderName)))
            {
                hasRecentActivity = true;
                if (entry.Level == 3)
                    warningCount++;
                else
                    infoCount++;
            }

            errorsIncomplete = errors.CapReached;
            activityIncomplete = others.CapReached;

            evidence.AppendLine($"\n  Last 7 days: {errors.CountText(errorCount)} errors, {others.CountText(warningCount)} warnings, {others.CountText(infoCount)} info");
            if ((errors.CapNote("Application") ?? others.CapNote("Application")) is { } capNote)
                evidence.AppendLine(capNote);

            if (errorCount > 0)
            {
                hasFailures = true;
                sb.AppendLine($"WARNING: {errors.CountText(errorCount)} backup error event(s) in the last 7 days. " +
                    "Investigate and resolve failed backups immediately.");
            }
            else if (errorsIncomplete)
            {
                sb.AppendLine($"REVIEW: The Application log held more than {errors.Cap} error events in the last 7 days, " +
                    "so older backup errors weren't checked. Check the backup console for failed jobs.");
            }
            else if (warningCount > 0)
            {
                sb.AppendLine($"INFO: {others.CountText(warningCount)} backup warning(s) in the last 7 days.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  Error reading event log: {ex.Message}");
        }
    }

    private static bool IsBackupSource(string provider) =>
        BackupSources.Any(s => provider.Contains(s, StringComparison.OrdinalIgnoreCase));

    private static bool IsVssSource(string provider) =>
        provider.Contains("VSS", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("Volume Shadow", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("volsnap", StringComparison.OrdinalIgnoreCase);

    private void CheckVssErrors(StringBuilder sb, StringBuilder evidence, ref bool hasFailures, CancellationToken ct)
    {
        evidence.AppendLine("\n[VSS Errors - System Log]");

        try
        {
            int vssErrors = 0;

            string query = EventLogQueryHelper.RecentEventsQuery(TimeSpan.FromDays(7), "Level=2");
            int sampled = 0;
            var read = _events.Query("System", query, EventLogQueryHelper.MaxEventsPerQuery,
                formatMessage: e => IsVssSource(e.ProviderName) && sampled++ < VssSampleCount, ct);
            foreach (var entry in read.Records)
            {
                string source = entry.ProviderName;
                if (IsVssSource(source))
                {
                    vssErrors++;
                    if (vssErrors <= VssSampleCount)
                    {
                        evidence.AppendLine($"  {entry.TimeCreated:yyyy-MM-dd HH:mm} " +
                            $"[{source}] {Truncate(entry.Message, 100)}");
                    }
                }
            }

            if (vssErrors > 0)
            {
                hasFailures = true;
                sb.AppendLine($"WARNING: {read.CountText(vssErrors)} VSS error(s) in the last 7 days. " +
                    "VSS failures can prevent backups from completing.");
            }

            evidence.AppendLine($"  VSS errors in last 7 days: {read.CountText(vssErrors)}");
            if (read.CapNote("System") is { } capNote)
                evidence.AppendLine(capNote);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
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

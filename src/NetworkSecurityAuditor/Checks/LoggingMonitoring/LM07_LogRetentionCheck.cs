namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM07 - Log retention and sizes: check Security, System, Application, PowerShell/Operational
/// log max sizes against CIS minimums. Check Sysmon installed. Report log mode.
/// </summary>
public sealed class LM07_LogRetentionCheck : ISecurityCheck
{
    public string Id => "LM07";

    // CIS L1 minimum log sizes in KB
    private static readonly (string LogName, string FriendlyName, long MinSizeKb)[] LogRequirements =
    [
        ("Security", "Security", 196_608),                                     // 192 MB
        ("System", "System", 32_768),                                          // 32 MB
        ("Application", "Application", 32_768),                                // 32 MB
        ("Microsoft-Windows-PowerShell/Operational", "PowerShell Operational", 32_768),  // 32 MB
        ("Windows PowerShell", "Windows PowerShell (legacy)", 16_384),         // 16 MB
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. Check each log's max size and mode
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Event Log Sizes & Retention]");

            foreach (var (logName, friendlyName, minSizeKb) in LogRequirements)
            {
                ct.ThrowIfCancellationRequested();
                CheckLogSize(logName, friendlyName, minSizeKb, sb, evidence, ref failCount, ref totalChecks);
            }

            // 2. Check Sysmon installed
            ct.ThrowIfCancellationRequested();
            totalChecks++;
            CheckSysmon(sb, evidence, ref failCount);

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount <= totalChecks / 3 ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"Log retention: {totalChecks - failCount}/{totalChecks} checks passed.\n");

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

    private static void CheckLogSize(string logName, string friendlyName, long minSizeKb,
        StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        evidence.AppendLine($"\n  [{friendlyName}]");

        try
        {
            using var session = new EventLogSession();
            var config = new EventLogConfiguration(logName, session);
            totalChecks++;

            long maxSizeKb = config.MaximumSizeInBytes / 1024;
            string logMode = config.LogMode.ToString();
            bool isEnabled = config.IsEnabled;

            evidence.AppendLine($"    Enabled: {isEnabled}");
            evidence.AppendLine($"    MaxSize: {maxSizeKb} KB ({config.MaximumSizeInBytes} bytes)");
            evidence.AppendLine($"    LogMode: {logMode}");

            if (!isEnabled)
            {
                failCount++;
                sb.AppendLine($"FAIL: {friendlyName} log is DISABLED.");
                return;
            }

            if (maxSizeKb >= minSizeKb)
            {
                sb.AppendLine($"{friendlyName}: {maxSizeKb} KB (>= {minSizeKb} KB CIS min), mode={logMode}.");
            }
            else
            {
                failCount++;
                sb.AppendLine($"FAIL: {friendlyName} log size is {maxSizeKb} KB (CIS requires >= {minSizeKb} KB).");
            }

            // Note if circular (overwrite) mode — events may be lost
            if (logMode == "Circular")
            {
                sb.AppendLine($"  INFO: {friendlyName} is in Circular mode (oldest events overwritten). Consider AutoBackup for retention.");
            }
        }
        catch (EventLogNotFoundException)
        {
            evidence.AppendLine($"    Log channel not found.");
            sb.AppendLine($"INFO: {friendlyName} log channel not found.");
        }
        catch (UnauthorizedAccessException)
        {
            evidence.AppendLine($"    Access denied.");
            sb.AppendLine($"INFO: Cannot query {friendlyName} log (requires administrator).");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"    Error: {ex.Message}");
        }
    }

    private static void CheckSysmon(StringBuilder sb, StringBuilder evidence, ref int failCount)
    {
        evidence.AppendLine("\n  [Sysmon]");

        bool sysmonFound = false;
        try
        {
            var services = ServiceController.GetServices();
            try
            {
                foreach (var svc in services)
                {
                    if (svc.ServiceName.Equals("Sysmon", StringComparison.OrdinalIgnoreCase) ||
                        svc.ServiceName.Equals("Sysmon64", StringComparison.OrdinalIgnoreCase))
                    {
                        sysmonFound = true;
                        evidence.AppendLine($"    Service: {svc.ServiceName} ({svc.Status})");
                        sb.AppendLine($"Sysmon: Installed ({svc.ServiceName}, status={svc.Status}).");
                        break;
                    }
                }
            }
            finally
            {
                ServiceControllerDisposal.DisposeAll(services);
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"    Error checking services: {ex.Message}");
        }

        if (!sysmonFound)
        {
            failCount++;
            evidence.AppendLine("    Sysmon not detected.");
            sb.AppendLine("WARNING: Sysmon is not installed. Sysmon provides critical process, network, and file-change telemetry.");
        }

        // Check Sysmon event log size if it exists
        if (sysmonFound)
        {
            try
            {
                using var session = new EventLogSession();
                var config = new EventLogConfiguration("Microsoft-Windows-Sysmon/Operational", session);
                long sysmonSizeKb = config.MaximumSizeInBytes / 1024;
                evidence.AppendLine($"    Sysmon log MaxSize: {sysmonSizeKb} KB, Mode: {config.LogMode}");

                if (sysmonSizeKb < 65_536) // 64 MB minimum for Sysmon
                {
                    sb.AppendLine($"WARNING: Sysmon log size is {sysmonSizeKb} KB. Consider increasing to >= 65,536 KB for adequate retention.");
                }
            }
            catch
            {
                evidence.AppendLine("    Sysmon event log not accessible.");
            }
        }
    }
}

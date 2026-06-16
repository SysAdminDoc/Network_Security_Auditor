namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.Diagnostics.Eventing.Reader;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM01 - DNS logging: DNS Client operational log state/size + DNS Server diagnostics (if role present).
/// </summary>
public sealed class LM01_DnsLoggingCheck : ISecurityCheck
{
    public string Id => "LM01";

    private const string DnsClientLogName = "Microsoft-Windows-DNS-Client/Operational";
    private const long MinLogSizeBytes = 1_048_576; // 1 MB minimum recommended

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. DNS Client operational log
            ct.ThrowIfCancellationRequested();
            CheckDnsClientLog(sb, evidence, ref failCount, ref totalChecks);

            // 2. DNS Server diagnostics (only if DNS Server role detected)
            ct.ThrowIfCancellationRequested();
            if (env.HasDNS)
            {
                CheckDnsServerDiagnostics(sb, evidence, ref failCount, ref totalChecks);
            }
            else
            {
                evidence.AppendLine("\n[DNS Server Diagnostics] Skipped (DNS Server role not detected).");
            }

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount < totalChecks ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"DNS logging: {totalChecks - failCount}/{totalChecks} checks passed.\n");

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

    private static void CheckDnsClientLog(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("[DNS Client Operational Log]");

        try
        {
            using var session = new EventLogSession();
            var config = new EventLogConfiguration(DnsClientLogName, session);

            bool isEnabled = config.IsEnabled;
            long maxSizeBytes = config.MaximumSizeInBytes;

            evidence.AppendLine($"  Enabled: {isEnabled}");
            evidence.AppendLine($"  MaxSize: {maxSizeBytes / 1024} KB ({maxSizeBytes} bytes)");
            evidence.AppendLine($"  LogMode: {config.LogMode}");

            if (isEnabled)
            {
                sb.AppendLine($"DNS Client operational log: Enabled (max {maxSizeBytes / 1024} KB, mode={config.LogMode}).");

                if (maxSizeBytes < MinLogSizeBytes)
                {
                    sb.AppendLine($"WARNING: DNS Client log max size ({maxSizeBytes / 1024} KB) is below recommended minimum ({MinLogSizeBytes / 1024} KB).");
                }
            }
            else
            {
                failCount++;
                sb.AppendLine("FAIL: DNS Client operational log (Microsoft-Windows-DNS-Client/Operational) is disabled.");
                sb.AppendLine("  Enable it for DNS query visibility and threat hunting.");
            }
        }
        catch (EventLogNotFoundException)
        {
            evidence.AppendLine("  Log channel not found.");
            sb.AppendLine("INFO: DNS Client operational log channel not found on this system.");
            totalChecks--;
        }
        catch (UnauthorizedAccessException)
        {
            evidence.AppendLine("  Access denied (requires admin).");
            sb.AppendLine("INFO: Cannot read DNS Client log configuration (requires administrator).");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
            sb.AppendLine($"INFO: Could not query DNS Client log: {ex.Message}");
        }
    }

    private static void CheckDnsServerDiagnostics(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[DNS Server Diagnostics]");

        // DNS Server analytical/audit logging via registry
        const string dnsServerKey = @"HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters";

        int eventLogLevel = RegistryHelper.GetValue<int>(dnsServerKey, "EventLogLevel", -1);
        int enableLogging = RegistryHelper.GetValue<int>(dnsServerKey, "EnableLogging", -1);

        evidence.AppendLine($"  EventLogLevel = {eventLogLevel}");
        evidence.AppendLine($"  EnableLogging = {enableLogging}");

        // Check DNS Server analytical log
        try
        {
            const string dnsServerAnalyticalLog = "Microsoft-Windows-DNSServer/Analytical";
            using var session = new EventLogSession();
            var config = new EventLogConfiguration(dnsServerAnalyticalLog, session);

            evidence.AppendLine($"  Analytical log enabled: {config.IsEnabled}");
            evidence.AppendLine($"  Analytical log max size: {config.MaximumSizeInBytes / 1024} KB");

            if (config.IsEnabled)
            {
                sb.AppendLine("DNS Server analytical log: Enabled.");
            }
            else
            {
                sb.AppendLine("WARNING: DNS Server analytical log is not enabled. Enable for full query-level DNS auditing.");
            }
        }
        catch
        {
            evidence.AppendLine("  DNS Server analytical log: not accessible.");
        }

        // Check DNS debug logging file
        string? logFilePath = RegistryHelper.GetValue<string>(dnsServerKey, "LogFilePath", null);
        evidence.AppendLine($"  LogFilePath = {logFilePath ?? "(not set)"}");

        if (eventLogLevel >= 4 || enableLogging == 1 || !string.IsNullOrEmpty(logFilePath))
        {
            sb.AppendLine("DNS Server diagnostics: Logging is configured.");
        }
        else
        {
            failCount++;
            sb.AppendLine("FAIL: DNS Server diagnostic logging is not configured. Enable query logging for security visibility.");
        }
    }
}

namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM04 - Firewall logging: per-profile log settings, LogBlocked, log file sizes.
/// CIS benchmark requires log size >= 16,384 KB.
/// </summary>
public sealed class LM04_FirewallLoggingCheck : ISecurityCheck
{
    public string Id => "LM04";

    private const int CisMinLogSizeKb = 16384;

    private static readonly string[] FirewallProfiles = ["DomainProfile", "StandardProfile", "PublicProfile"];

    private static readonly Dictionary<string, string> ProfileLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        { "DomainProfile", "Domain" },
        { "StandardProfile", "Private" },
        { "PublicProfile", "Public" },
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            evidence.AppendLine("[Windows Firewall Logging - Per Profile]");

            foreach (string profile in FirewallProfiles)
            {
                ct.ThrowIfCancellationRequested();
                CheckProfile(profile, sb, evidence, ref failCount, ref totalChecks);
            }

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount <= totalChecks / 2 ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"Firewall logging: {totalChecks - failCount}/{totalChecks} checks passed.\n");

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

    private static void CheckProfile(string profile, StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        string label = ProfileLabels.GetValueOrDefault(profile, profile);
        string basePath = $@"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}\Logging";
        string fallbackPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\Logging";

        evidence.AppendLine($"\n  [{label} Profile]");

        // Try policy path first, fall back to system path
        string activePath = RegistryHelper.KeyExists(basePath) ? basePath : fallbackPath;
        evidence.AppendLine($"    Source: {(activePath == basePath ? "GPO" : "Local")}");

        // LogBlocked (LogDroppedPackets)
        totalChecks++;
        int logBlocked = RegistryHelper.GetValue<int>(activePath, "LogDroppedPackets", -1);
        evidence.AppendLine($"    LogDroppedPackets = {logBlocked}");

        if (logBlocked == 1)
        {
            sb.AppendLine($"{label}: Blocked packets are logged.");
        }
        else
        {
            failCount++;
            sb.AppendLine($"FAIL: {label} profile does not log blocked (dropped) packets.");
        }

        // LogSuccessfulConnections
        totalChecks++;
        int logAllowed = RegistryHelper.GetValue<int>(activePath, "LogSuccessfulConnections", -1);
        evidence.AppendLine($"    LogSuccessfulConnections = {logAllowed}");

        if (logAllowed == 1)
        {
            sb.AppendLine($"{label}: Successful connections are logged.");
        }
        else
        {
            // Not logging allowed connections is less critical but noted
            sb.AppendLine($"INFO: {label} profile does not log successful connections (useful for forensics).");
        }

        // Log file size
        totalChecks++;
        int logSizeKb = RegistryHelper.GetValue<int>(activePath, "LogFileSize", -1);
        evidence.AppendLine($"    LogFileSize = {(logSizeKb == -1 ? "not set" : $"{logSizeKb} KB")}");

        if (logSizeKb >= CisMinLogSizeKb)
        {
            sb.AppendLine($"{label}: Log file size {logSizeKb} KB meets CIS minimum ({CisMinLogSizeKb} KB).");
        }
        else if (logSizeKb > 0)
        {
            failCount++;
            sb.AppendLine($"FAIL: {label} log file size is {logSizeKb} KB (CIS requires >= {CisMinLogSizeKb} KB).");
        }
        else
        {
            failCount++;
            sb.AppendLine($"FAIL: {label} log file size is not configured (CIS requires >= {CisMinLogSizeKb} KB).");
        }

        // Log file path
        string? logFilePath = RegistryHelper.GetValue<string>(activePath, "LogFilePath", null);
        evidence.AppendLine($"    LogFilePath = {logFilePath ?? "(default)"}");
    }
}

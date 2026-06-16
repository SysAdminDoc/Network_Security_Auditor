namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.ServiceProcess;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM06 - File Integrity Monitoring: detect Sysmon, Tripwire, OSSEC, Wazuh,
/// and file auditing GPO settings.
/// </summary>
public sealed class LM06_FimCheck : ISecurityCheck
{
    public string Id => "LM06";

    private static readonly (string ServiceName, string Label)[] FimServices =
    [
        ("Sysmon", "Sysmon (System Monitor)"),
        ("Sysmon64", "Sysmon64 (System Monitor 64-bit)"),
        ("Tripwire", "Tripwire Enterprise Agent"),
        ("twagent", "Tripwire Agent"),
        ("OssecSvc", "OSSEC Agent"),
        ("WazuhSvc", "Wazuh Agent"),
        ("osqueryd", "osquery Daemon"),
        ("CarbonBlack", "Carbon Black (FIM capability)"),
        ("CbDefense", "Carbon Black Cloud (FIM capability)"),
        ("SentinelAgent", "SentinelOne (FIM capability)"),
    ];

    private static readonly (string KeyPath, string Label)[] FimRegistryKeys =
    [
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon", "Sysmon"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64", "Sysmon64"),
        (@"HKLM\SOFTWARE\Tripwire", "Tripwire"),
        (@"HKLM\SOFTWARE\ossec-agent", "OSSEC/Wazuh"),
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            var detectedTools = new List<string>();

            // 1. Service-based FIM detection
            ct.ThrowIfCancellationRequested();
            DetectFimServices(evidence, detectedTools, ct);

            // 2. Registry-based detection
            ct.ThrowIfCancellationRequested();
            DetectFimRegistry(evidence, detectedTools);

            // 3. Sysmon config verification (if Sysmon detected)
            ct.ThrowIfCancellationRequested();
            if (detectedTools.Any(t => t.Contains("Sysmon", StringComparison.OrdinalIgnoreCase)))
            {
                CheckSysmonConfig(sb, evidence);
            }

            // 4. File auditing GPO (Object Access auditing)
            ct.ThrowIfCancellationRequested();
            CheckFileAuditing(sb, evidence, detectedTools);

            // Summarize
            if (detectedTools.Count > 0)
            {
                var unique = detectedTools.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                sb.Insert(0, $"File Integrity Monitoring: {unique.Count} tool(s)/capability(ies) detected.\n");
                sb.AppendLine($"Detected: {string.Join(", ", unique)}");
            }
            else
            {
                sb.Insert(0, "FAIL: No file integrity monitoring (FIM) tools detected.\n");
                sb.AppendLine("  Consider deploying Sysmon (free), OSSEC/Wazuh, Tripwire, or enabling file auditing via GPO.");
                sb.AppendLine("  FIM is required by PCI DSS (Req 10.5.5 / 11.5), HIPAA, and recommended by CIS.");
            }

            var status = detectedTools.Count > 0 ? CheckStatus.Pass : CheckStatus.Fail;

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

    private static void DetectFimServices(StringBuilder evidence, List<string> detected, CancellationToken ct)
    {
        evidence.AppendLine("[FIM Service Detection]");

        try
        {
            var services = ServiceController.GetServices();
            var serviceNames = new HashSet<string>(
                services.Select(s => s.ServiceName),
                StringComparer.OrdinalIgnoreCase);

            foreach (var (serviceName, label) in FimServices)
            {
                ct.ThrowIfCancellationRequested();

                if (!serviceNames.Contains(serviceName)) continue;

                try
                {
                    using var sc = new ServiceController(serviceName);
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - Status: {sc.Status}");
                    detected.Add(label);
                }
                catch
                {
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - Status: unknown");
                    detected.Add(label);
                }
            }

            if (detected.Count == 0)
                evidence.AppendLine("  No FIM services detected.");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error enumerating services: {ex.Message}");
        }
    }

    private static void DetectFimRegistry(StringBuilder evidence, List<string> detected)
    {
        evidence.AppendLine("\n[FIM Registry Detection]");

        foreach (var (keyPath, label) in FimRegistryKeys)
        {
            if (RegistryHelper.KeyExists(keyPath))
            {
                evidence.AppendLine($"  FOUND: {label} ({keyPath})");
                if (!detected.Any(d => d.Contains(label, StringComparison.OrdinalIgnoreCase)))
                    detected.Add(label);
            }
        }
    }

    private static void CheckSysmonConfig(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[Sysmon Configuration]");

        // Sysmon stores its config hash in the registry
        string? configHash = RegistryHelper.GetValue<string>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters", "HashingAlgorithm", null);
        string? configPath = RegistryHelper.GetValue<string>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters", "ConfigFile", null);

        // Try Sysmon64 path too
        configHash ??= RegistryHelper.GetValue<string>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64\Parameters", "HashingAlgorithm", null);

        evidence.AppendLine($"  ConfigFile = {configPath ?? "(embedded/default)"}");
        evidence.AppendLine($"  HashingAlgorithm = {configHash ?? "(not set)"}");

        // Check for common Sysmon event IDs being generated (driver load = presence indicator)
        string? driverName = RegistryHelper.GetValue<string>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv", "ImagePath", null);
        driverName ??= RegistryHelper.GetValue<string>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv", "DisplayName", null);

        evidence.AppendLine($"  SysmonDrv ImagePath = {driverName ?? "(not found)"}");

        if (driverName != null)
        {
            sb.AppendLine("Sysmon: Driver loaded, actively monitoring.");
        }
        else
        {
            sb.AppendLine("WARNING: Sysmon service found but driver (SysmonDrv) not detected. Sysmon may not be fully operational.");
        }
    }

    private static void CheckFileAuditing(StringBuilder sb, StringBuilder evidence, List<string> detected)
    {
        evidence.AppendLine("\n[File Auditing GPO]");

        // Check if Object Access auditing is enabled (indicates file audit SACLs may be active)
        // This is set via Advanced Audit Policy -> Object Access -> Audit File System
        int auditFileSystem = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AuditPolicy", "AuditFileSystem", -1);

        evidence.AppendLine($"  AuditFileSystem = {auditFileSystem}");

        // Also check via the more common path
        bool objectAccessAudit = RegistryHelper.GetValue<int>(
            @"HKLM\SECURITY\Policy\PolAdtEv", "", -1) != -1;

        evidence.AppendLine($"  PolAdtEv key exists = {objectAccessAudit}");

        // A more reliable indicator: check if any SACL-related audit subcategory is configured
        int auditObjectAccess = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ObjectAccess", -1);

        evidence.AppendLine($"  ObjectAccess audit policy = {auditObjectAccess}");

        if (auditObjectAccess >= 1)
        {
            detected.Add("Windows File Auditing (Object Access)");
            sb.AppendLine("File auditing: Object Access audit policy is configured.");
        }
    }
}

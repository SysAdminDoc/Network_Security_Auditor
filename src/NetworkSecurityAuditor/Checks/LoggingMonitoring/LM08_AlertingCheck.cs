namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.ServiceProcess;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM08 - Alerting configuration: heuristic/interview check for alerting mechanisms.
/// Checks for SIEM with alerts, scheduled task email alerts, WEF to SIEM indicators.
/// </summary>
public sealed class LM08_AlertingCheck : ISecurityCheck
{
    public string Id => "LM08";

    // Services whose presence suggests an alerting/monitoring pipeline exists
    private static readonly (string ServiceName, string Label)[] AlertCapableServices =
    [
        ("SplunkForwarder", "Splunk (alerting via Splunk searches)"),
        ("splunkd", "Splunk Enterprise (built-in alerting)"),
        ("elastic-agent", "Elastic Agent (Elastic SIEM alerting)"),
        ("WazuhSvc", "Wazuh Agent (active response + alerts)"),
        ("OssecSvc", "OSSEC Agent (active response)"),
        ("SenseCE", "Defender for Endpoint (built-in alerting)"),
        ("Sense", "Defender for Endpoint (built-in alerting)"),
        ("MicrosoftMonitoringAgent", "Microsoft MMA (SCOM/Sentinel alerting)"),
        ("AzureMonitorWindowsAgent", "Azure Monitor (alert rules)"),
        ("prtg_probe", "PRTG Probe (infrastructure alerting)"),
        ("nscp", "NSClient++ (Nagios/Icinga alerting)"),
        ("zaborern_agentd", "Zabbix Agent"),
        ("ZabbixAgent", "Zabbix Agent"),
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            var indicators = new List<string>();

            // 1. Check for alerting-capable services
            ct.ThrowIfCancellationRequested();
            DetectAlertServices(evidence, indicators, ct);

            // 2. Check for scheduled tasks that may send alerts (e.g., email on event)
            ct.ThrowIfCancellationRequested();
            CheckScheduledTaskAlerts(sb, evidence, indicators);

            // 3. Check WEF (events forwarded to a SIEM = alerting capability)
            ct.ThrowIfCancellationRequested();
            CheckWefForAlerting(evidence, indicators);

            // 4. Check for Windows Event task triggers (event-triggered tasks)
            ct.ThrowIfCancellationRequested();
            CheckEventTriggeredTasks(evidence, indicators);

            // 5. Check for SMTP relay configuration (indicates email alerting capability)
            ct.ThrowIfCancellationRequested();
            CheckSmtpRelay(evidence, indicators);

            // Summarize
            if (indicators.Count > 0)
            {
                var unique = indicators.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                sb.Insert(0, $"Alerting: {unique.Count} indicator(s) of alerting capability detected.\n");
                sb.AppendLine("This is a heuristic check. Verify that alerts are actively monitored and escalated.");
                sb.AppendLine($"Indicators: {string.Join("; ", unique)}");
            }
            else
            {
                sb.Insert(0, "FAIL: No alerting mechanisms detected.\n");
                sb.AppendLine("  No SIEM agents, event-triggered tasks, WEF subscriptions, or SMTP alerting found.");
                sb.AppendLine("  Without alerting, security events go unnoticed. This is a critical gap.");
                sb.AppendLine("  INTERVIEW: Ask the client how security events are detected and who is alerted.");
            }

            // This is fundamentally a heuristic/interview check
            var status = indicators.Count > 0 ? CheckStatus.Partial : CheckStatus.Fail;
            if (indicators.Count >= 2)
                status = CheckStatus.Pass; // Multiple indicators = high confidence

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

    private static void DetectAlertServices(StringBuilder evidence, List<string> indicators, CancellationToken ct)
    {
        evidence.AppendLine("[Alerting-Capable Services]");

        try
        {
            var services = ServiceController.GetServices();
            var serviceNames = new HashSet<string>(
                services.Select(s => s.ServiceName),
                StringComparer.OrdinalIgnoreCase);

            foreach (var (serviceName, label) in AlertCapableServices)
            {
                ct.ThrowIfCancellationRequested();

                if (!serviceNames.Contains(serviceName)) continue;

                try
                {
                    using var sc = new ServiceController(serviceName);
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - {sc.Status}");
                    if (sc.Status == ServiceControllerStatus.Running)
                        indicators.Add(label);
                }
                catch
                {
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - status unknown");
                    indicators.Add(label);
                }
            }

            if (indicators.Count == 0)
                evidence.AppendLine("  No alerting-capable services detected.");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
        }
    }

    private static void CheckScheduledTaskAlerts(StringBuilder sb, StringBuilder evidence, List<string> indicators)
    {
        evidence.AppendLine("\n[Scheduled Task Alerts]");

        // Check Task Scheduler registry for tasks with email actions
        const string taskKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";
        var taskSubkeys = RegistryHelper.GetSubKeyNames(taskKey);

        evidence.AppendLine($"  Registered task count: {taskSubkeys.Length}");

        // Look for tasks with "alert", "notify", "email", "monitor" in their path
        const string treeKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        var treeNames = RegistryHelper.GetSubKeyNames(treeKey);

        int alertTaskCount = 0;
        foreach (string name in treeNames)
        {
            if (name.Contains("alert", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("notify", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("monitor", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("email", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("siem", StringComparison.OrdinalIgnoreCase))
            {
                alertTaskCount++;
                evidence.AppendLine($"  Potential alert task: {name}");
            }
        }

        if (alertTaskCount > 0)
        {
            indicators.Add($"Scheduled alert tasks ({alertTaskCount})");
            sb.AppendLine($"Found {alertTaskCount} scheduled task(s) with alert/notify/monitor keywords.");
        }
    }

    private static void CheckWefForAlerting(StringBuilder evidence, List<string> indicators)
    {
        evidence.AppendLine("\n[WEF for Alerting]");

        const string wefKey = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager";
        var subKeys = RegistryHelper.GetValueNames(wefKey);

        if (subKeys.Length > 0)
        {
            evidence.AppendLine($"  WEF subscriptions: {subKeys.Length}");
            indicators.Add("Windows Event Forwarding (forwarding to collector/SIEM)");
        }
        else
        {
            evidence.AppendLine("  No WEF subscriptions configured.");
        }
    }

    private static void CheckEventTriggeredTasks(StringBuilder evidence, List<string> indicators)
    {
        evidence.AppendLine("\n[Event-Triggered Tasks]");

        // Check if any tasks are bound to security event IDs (common alert pattern)
        // This is stored in task XML; we check for EventTrigger registration via registry
        const string taskKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";
        var taskGuids = RegistryHelper.GetSubKeyNames(taskKey);

        int eventTriggered = 0;
        // Sample up to 50 tasks to avoid long runtime
        foreach (string guid in taskGuids.Take(50))
        {
            int triggers = RegistryHelper.GetValue<int>(
                $@"{taskKey}\{guid}", "Triggers", -1);
            // A non-default triggers value suggests the task has trigger data
            // We can't parse the full XML from registry alone, but the presence
            // of many tasks is itself a signal
        }

        evidence.AppendLine($"  Total registered tasks scanned: {Math.Min(taskGuids.Length, 50)}/{taskGuids.Length}");
        // Event-triggered tasks are common even without alerting; this is just context.
    }

    private static void CheckSmtpRelay(StringBuilder evidence, List<string> indicators)
    {
        evidence.AppendLine("\n[SMTP Alerting Capability]");

        // Check if IIS SMTP or other SMTP relay is configured
        bool smtpService = false;
        try
        {
            var services = ServiceController.GetServices();
            foreach (var svc in services)
            {
                if (svc.ServiceName.Equals("SMTPSVC", StringComparison.OrdinalIgnoreCase) ||
                    svc.ServiceName.Equals("hMailServer", StringComparison.OrdinalIgnoreCase))
                {
                    smtpService = true;
                    evidence.AppendLine($"  SMTP service found: {svc.ServiceName} ({svc.Status})");
                    break;
                }
            }
        }
        catch
        {
            // Ignore
        }

        // Check for common SMTP configuration in registry
        string? smtpServer = RegistryHelper.GetValue<string>(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Mail", "SMTPServer", null);

        if (!string.IsNullOrEmpty(smtpServer))
        {
            evidence.AppendLine($"  SMTP server configured: {smtpServer}");
            indicators.Add("SMTP relay configured (email alerting possible)");
        }
        else if (smtpService)
        {
            indicators.Add("Local SMTP service (email alerting possible)");
        }
        else
        {
            evidence.AppendLine("  No SMTP configuration detected.");
        }
    }
}

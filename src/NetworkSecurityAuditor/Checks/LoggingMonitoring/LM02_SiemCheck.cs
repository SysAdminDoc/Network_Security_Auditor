namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;


using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM02 - SIEM / Centralized logging: detect SIEM agent services, registry indicators,
/// and Windows Event Forwarding (WEF) subscriptions.
/// </summary>
public sealed class LM02_SiemCheck : ISecurityCheck
{
    public string Id => "LM02";

    // Service name -> friendly label for known SIEM/log-forwarding agents
    private static readonly (string ServiceName, string Label)[] SiemServices =
    [
        ("SplunkForwarder", "Splunk Universal Forwarder"),
        ("splunkd", "Splunk Enterprise/Forwarder"),
        ("elastic-agent", "Elastic Agent"),
        ("elastic-endpoint", "Elastic Endpoint Security"),
        ("filebeat", "Elastic Filebeat"),
        ("winlogbeat", "Elastic Winlogbeat"),
        ("WazuhSvc", "Wazuh Agent"),
        ("OssecSvc", "OSSEC Agent"),
        ("MicrosoftMonitoringAgent", "Microsoft Monitoring Agent (MMA/SCOM)"),
        ("HealthService", "Microsoft MMA Health Service"),
        ("SenseCE", "Microsoft Defender for Endpoint (Sense)"),
        ("Sense", "Microsoft Defender for Endpoint (Sense)"),
        ("AzureMonitorWindowsAgent", "Azure Monitor Agent (AMA)"),
        ("WindowsAzureGuestAgent", "Azure Guest Agent"),
        ("nxlog", "NXLog"),
        ("Wecsvc", "Windows Event Collector"),
        ("EventLog", "Windows Event Log"),
        ("rsyslog", "rsyslog (unlikely on Windows)"),
        ("fluentd", "Fluentd"),
        ("td-agent", "Fluentd (td-agent)"),
        ("QualysAgent", "Qualys Cloud Agent"),
        ("CarbonBlackClientSetup", "Carbon Black Agent"),
        ("CbDefense", "Carbon Black Cloud"),
    ];

    // Registry paths that indicate SIEM integration
    private static readonly (string KeyPath, string Label)[] SiemRegistryKeys =
    [
        (@"HKLM\SOFTWARE\Splunk", "Splunk"),
        (@"HKLM\SOFTWARE\Elastic", "Elastic"),
        (@"HKLM\SOFTWARE\ossec-agent", "OSSEC/Wazuh"),
        (@"HKLM\SOFTWARE\Microsoft\Microsoft Monitoring Agent", "Microsoft Monitoring Agent"),
        (@"HKLM\SOFTWARE\Microsoft\Azure Monitor", "Azure Monitor Agent"),
        (@"HKLM\SOFTWARE\nxlog", "NXLog"),
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            var detectedAgents = new List<string>();

            // 1. Service detection
            ct.ThrowIfCancellationRequested();
            DetectSiemServices(evidence, detectedAgents, ct);

            // 2. Registry detection
            ct.ThrowIfCancellationRequested();
            DetectSiemRegistry(evidence, detectedAgents);

            // 3. Windows Event Forwarding (WEF)
            ct.ThrowIfCancellationRequested();
            bool wefConfigured = CheckWef(sb, evidence);
            if (wefConfigured)
                detectedAgents.Add("Windows Event Forwarding (WEF)");

            // Summarize
            if (detectedAgents.Count > 0)
            {
                var unique = detectedAgents.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                sb.Insert(0, $"SIEM/centralized logging: {unique.Count} agent(s) detected.\n");
                sb.AppendLine($"Detected: {string.Join(", ", unique)}");
            }
            else
            {
                sb.Insert(0, "FAIL: No SIEM agent or centralized log forwarding detected.\n");
                sb.AppendLine("  Consider deploying a SIEM forwarder (Splunk UF, Elastic Agent, Wazuh, Azure Monitor Agent, etc.).");
                sb.AppendLine("  Without centralized logging, incident response and threat detection are severely limited.");
            }

            var status = detectedAgents.Count > 0 ? CheckStatus.Pass : CheckStatus.Fail;

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

    private static void DetectSiemServices(StringBuilder evidence, List<string> detected, CancellationToken ct)
    {
        evidence.AppendLine("[SIEM Service Detection]");

        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT Name, State FROM Win32_Service");
            var serviceMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString();
                var state = obj["State"]?.ToString();
                if (name is not null) serviceMap[name] = state ?? "Unknown";
            }

            foreach (var (serviceName, label) in SiemServices)
            {
                ct.ThrowIfCancellationRequested();

                if (serviceMap.TryGetValue(serviceName, out var status))
                {
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - Status: {status}");
                    detected.Add(label);
                }
            }

            if (detected.Count == 0)
                evidence.AppendLine("  No SIEM agent services detected.");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error enumerating services: {ex.Message}");
        }
    }

    private static void DetectSiemRegistry(StringBuilder evidence, List<string> detected)
    {
        evidence.AppendLine("\n[SIEM Registry Detection]");

        foreach (var (keyPath, label) in SiemRegistryKeys)
        {
            if (RegistryHelper.KeyExists(keyPath))
            {
                evidence.AppendLine($"  FOUND: {label} ({keyPath})");
                if (!detected.Any(d => d.Contains(label, StringComparison.OrdinalIgnoreCase)))
                    detected.Add(label);
            }
        }
    }

    private static bool CheckWef(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[Windows Event Forwarding (WEF)]");

        // Check if WinRM is configured for event forwarding
        // Subscription manager registry
        const string wefKey = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager";
        var subKeys = RegistryHelper.GetValueNames(wefKey);

        if (subKeys.Length > 0)
        {
            evidence.AppendLine($"  WEF SubscriptionManager: {subKeys.Length} subscription(s) configured.");
            foreach (string name in subKeys)
            {
                string? val = RegistryHelper.GetValue<string>(wefKey, name, null);
                evidence.AppendLine($"    {name} = {val ?? "(null)"}");
            }
            sb.AppendLine("Windows Event Forwarding: Subscription(s) configured.");
            return true;
        }

        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT State FROM Win32_Service WHERE Name = 'Wecsvc'");
            foreach (var obj in searcher.Get())
            {
                var state = obj["State"]?.ToString() ?? "Unknown";
                evidence.AppendLine($"  Windows Event Collector (Wecsvc): {state}");
                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    sb.AppendLine("Windows Event Collector service is running (this machine is a WEF collector).");
                    return true;
                }
            }
        }
        catch
        {
            evidence.AppendLine("  Windows Event Collector service: not found.");
        }

        evidence.AppendLine("  No WEF subscriptions or collector detected.");
        return false;
    }
}

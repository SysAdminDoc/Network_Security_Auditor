namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;


using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM02 - SIEM / Centralized logging: detect running log-forwarding agents, onboarded
/// Defender for Endpoint, and Windows Event Forwarding source or collector subscriptions.
/// Inbox services that exist on every host (EventLog, an idle Wecsvc, an unonboarded
/// Sense) never count as central collection.
/// </summary>
public sealed class LM02_SiemCheck : ISecurityCheck
{
    public string Id => "LM02";

    internal const string MdeServiceName = "Sense";
    internal const string CollectorServiceName = "Wecsvc";
    internal const string MdeStatusKey = @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status";
    internal const string WefSubscriptionManagerKey = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager";
    internal const string CollectorSubscriptionsKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions";

    // Service name -> friendly label for third-party log-forwarding agents. Only a running
    // service counts; an installed but stopped agent is reported without credit.
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
        ("AzureMonitorAgent", "Azure Monitor Agent (AMA)"),
        ("AzureMonitorWindowsAgent", "Azure Monitor Agent (AMA)"),
        ("nxlog", "NXLog"),
        ("rsyslog", "rsyslog (unlikely on Windows)"),
        ("fluentd", "Fluentd"),
        ("td-agent", "Fluentd (td-agent)"),
        ("QualysAgent", "Qualys Cloud Agent"),
        ("CarbonBlackClientSetup", "Carbon Black Agent"),
        ("CbDefense", "Carbon Black Cloud"),
    ];

    // Registry paths left by SIEM agents, with the services that prove the agent is present.
    // A key on its own is an install trace, not proof of forwarding.
    private static readonly (string KeyPath, string Label, string[] ServiceNames)[] SiemRegistryKeys =
    [
        (@"HKLM\SOFTWARE\Splunk", "Splunk", ["SplunkForwarder", "splunkd"]),
        (@"HKLM\SOFTWARE\Elastic", "Elastic", ["elastic-agent", "elastic-endpoint", "filebeat", "winlogbeat"]),
        (@"HKLM\SOFTWARE\ossec-agent", "OSSEC/Wazuh", ["WazuhSvc", "OssecSvc"]),
        (@"HKLM\SOFTWARE\Microsoft\Microsoft Monitoring Agent", "Microsoft Monitoring Agent", ["MicrosoftMonitoringAgent", "HealthService"]),
        (@"HKLM\SOFTWARE\Microsoft\Azure Monitor", "Azure Monitor Agent", ["AzureMonitorAgent", "AzureMonitorWindowsAgent"]),
        (@"HKLM\SOFTWARE\nxlog", "NXLog", ["nxlog"]),
    ];

    internal static IReadOnlyList<string> RegistryIndicatorPaths => SiemRegistryKeys.Select(k => k.KeyPath).ToArray();

    /// <summary>Everything LM02 reads from the host, so the decision can be tested with fixtures.</summary>
    internal sealed record SiemSnapshot
    {
        /// <summary>Service name to Win32_Service State; null when enumeration failed.</summary>
        public IReadOnlyDictionary<string, string>? Services { get; init; }
        public string? ServiceEnumerationError { get; init; }
        /// <summary>Paths from <see cref="RegistryIndicatorPaths"/> that exist on the host.</summary>
        public IReadOnlyList<string> RegistryKeysPresent { get; init; } = [];
        /// <summary>WEF source-initiated SubscriptionManager policy values (this host forwards).</summary>
        public IReadOnlyList<string> ForwardingTargets { get; init; } = [];
        /// <summary>Subscriptions defined on this host as a WEF collector.</summary>
        public IReadOnlyList<string> CollectorSubscriptions { get; init; } = [];
        /// <summary>OnboardingState DWORD, or null when the value is absent.</summary>
        public int? MdeOnboardingState { get; init; }
    }

    internal sealed record SiemAssessment(
        CheckStatus Status,
        string Findings,
        string Evidence,
        IReadOnlyList<string> CountedSources,
        string? Error);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var snapshot = CollectSnapshot(ct);
            var assessment = Assess(snapshot);

            return Task.FromResult(new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence,
                Error = assessment.Error
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static SiemAssessment Assess(SiemSnapshot snapshot)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        var counted = new List<string>();
        var notCounted = new List<string>();
        var services = snapshot.Services;

        evidence.AppendLine("[SIEM Service Detection]");
        if (services is null)
        {
            evidence.AppendLine($"  Error enumerating services: {snapshot.ServiceEnumerationError ?? "unknown error"}");
        }
        else
        {
            foreach (var (serviceName, label) in SiemServices)
            {
                if (!services.TryGetValue(serviceName, out var state))
                    continue;
                if (IsRunning(state))
                {
                    evidence.AppendLine($"  FOUND: {label} ({serviceName}) - Status: {state}");
                    AddDistinct(counted, label);
                }
                else
                {
                    evidence.AppendLine($"  INSTALLED, NOT RUNNING: {label} ({serviceName}) - Status: {state}; not counted");
                    AddDistinct(notCounted, $"{label} ({state})");
                }
            }
            if (counted.Count == 0 && notCounted.Count == 0)
                evidence.AppendLine("  No third-party log-forwarding agent services detected.");

            if (services.TryGetValue("EventLog", out var eventLogState))
                evidence.AppendLine($"  Windows Event Log (EventLog) - Status: {eventLogState}; local logging only, not counted as central collection.");
        }

        AssessDefenderForEndpoint(snapshot, services, evidence, counted, notCounted);
        AssessEventForwarding(snapshot, services, sb, evidence, counted, notCounted);

        evidence.AppendLine("\n[SIEM Registry Indicators]");
        var tracesWithoutService = new List<string>();
        var present = SiemRegistryKeys
            .Where(k => snapshot.RegistryKeysPresent.Contains(k.KeyPath, StringComparer.OrdinalIgnoreCase))
            .ToList();
        if (present.Count == 0)
        {
            evidence.AppendLine("  None found.");
        }
        foreach (var (keyPath, label, serviceNames) in present)
        {
            bool corroborated = services is not null && serviceNames.Any(services.ContainsKey);
            evidence.AppendLine(corroborated
                ? $"  FOUND: {label} ({keyPath}); matches a detected service."
                : $"  FOUND: {label} ({keyPath}); install trace only, no matching service seen.");
            if (!corroborated)
                AddDistinct(tracesWithoutService, label);
        }

        CheckStatus status;
        string? error = null;
        if (counted.Count > 0)
        {
            status = CheckStatus.Pass;
            sb.Insert(0, $"SIEM/centralized logging: {counted.Count} active source(s) detected.\n");
            sb.AppendLine($"Detected: {string.Join(", ", counted)}");
            if (notCounted.Count > 0)
                sb.AppendLine($"Also installed but not forwarding: {string.Join(", ", notCounted)}");
        }
        else if (services is null)
        {
            status = CheckStatus.NotAssessed;
            error = snapshot.ServiceEnumerationError ?? "Service enumeration failed.";
            sb.Insert(0, "NOT ASSESSED: services couldn't be enumerated, so running log-forwarding agents can't be confirmed.\n");
        }
        else if (tracesWithoutService.Count > 0 && notCounted.Count == 0)
        {
            status = CheckStatus.Partial;
            sb.Insert(0, "PARTIAL: SIEM agent install traces found, but no running forwarding service was matched.\n");
            sb.AppendLine($"  Traces: {string.Join(", ", tracesWithoutService)}. Confirm the agent is reporting in the SIEM console.");
        }
        else
        {
            status = CheckStatus.Fail;
            sb.Insert(0, "FAIL: No active SIEM agent or centralized log forwarding detected.\n");
            if (notCounted.Count > 0)
                sb.AppendLine($"  Installed but not forwarding: {string.Join(", ", notCounted)}. Start or repair the agent.");
            sb.AppendLine("  Consider deploying a SIEM forwarder (Splunk UF, Elastic Agent, Wazuh, Azure Monitor Agent, etc.).");
            sb.AppendLine("  Without centralized logging, incident response and threat detection are severely limited.");
        }

        return new SiemAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd(), counted, error);
    }

    private static void AssessDefenderForEndpoint(
        SiemSnapshot snapshot,
        IReadOnlyDictionary<string, string>? services,
        StringBuilder evidence,
        List<string> counted,
        List<string> notCounted)
    {
        evidence.AppendLine("\n[Microsoft Defender for Endpoint]");
        string? senseState = null;
        bool senseKnown = services is not null && services.TryGetValue(MdeServiceName, out senseState);
        bool onboarded = snapshot.MdeOnboardingState == 1;
        string onboarding = snapshot.MdeOnboardingState?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "absent";
        evidence.AppendLine($"  Sense service: {(senseKnown ? senseState : "not found")}; OnboardingState: {onboarding}");

        if (!senseKnown)
            return;
        if (onboarded && IsRunning(senseState))
        {
            AddDistinct(counted, "Microsoft Defender for Endpoint (onboarded)");
        }
        else if (onboarded)
        {
            evidence.AppendLine("  Onboarded, but the Sense service isn't running; not counted.");
            AddDistinct(notCounted, $"Microsoft Defender for Endpoint ({senseState})");
        }
        else
        {
            evidence.AppendLine("  The Sense service ships with Windows; without OnboardingState = 1 it sends nothing.");
        }
    }

    private static void AssessEventForwarding(
        SiemSnapshot snapshot,
        IReadOnlyDictionary<string, string>? services,
        StringBuilder sb,
        StringBuilder evidence,
        List<string> counted,
        List<string> notCounted)
    {
        evidence.AppendLine("\n[Windows Event Forwarding (WEF)]");
        if (snapshot.ForwardingTargets.Count > 0)
        {
            evidence.AppendLine($"  WEF SubscriptionManager: {snapshot.ForwardingTargets.Count} target(s) configured.");
            foreach (var target in snapshot.ForwardingTargets)
                evidence.AppendLine($"    {target}");
            sb.AppendLine("Windows Event Forwarding: this host forwards events to a collector.");
            AddDistinct(counted, "Windows Event Forwarding (WEF)");
        }

        string? collectorState = null;
        bool collectorKnown = services is not null && services.TryGetValue(CollectorServiceName, out collectorState);
        int subscriptions = snapshot.CollectorSubscriptions.Count;
        evidence.AppendLine($"  Windows Event Collector (Wecsvc): {(collectorKnown ? collectorState : "not found")}; subscriptions: {subscriptions}");
        foreach (var name in snapshot.CollectorSubscriptions.Take(10))
            evidence.AppendLine($"    {name}");

        if (subscriptions == 0)
        {
            if (collectorKnown && IsRunning(collectorState))
                evidence.AppendLine("  Wecsvc is running with no subscriptions, so this host collects nothing; not counted.");
            if (snapshot.ForwardingTargets.Count == 0)
                evidence.AppendLine("  No WEF subscriptions or collector detected.");
            return;
        }
        if (collectorKnown && IsRunning(collectorState))
        {
            sb.AppendLine($"Windows Event Collector: {subscriptions} subscription(s) on this host.");
            AddDistinct(counted, "Windows Event Collector (WEF)");
        }
        else
        {
            evidence.AppendLine("  Subscriptions exist, but the collector service isn't running; not counted.");
            AddDistinct(notCounted, $"Windows Event Collector ({collectorState ?? "not found"})");
        }
    }

    private static bool IsRunning(string? state) =>
        string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase);

    private static void AddDistinct(List<string> list, string value)
    {
        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase))
            list.Add(value);
    }

    private static SiemSnapshot CollectSnapshot(CancellationToken ct)
    {
        Dictionary<string, string>? services = null;
        string? serviceError = null;
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT Name, State FROM Win32_Service");
            services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                var name = obj["Name"]?.ToString();
                if (name is not null) services[name] = obj["State"]?.ToString() ?? "Unknown";
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            services = null;
            serviceError = ex.Message;
        }

        ct.ThrowIfCancellationRequested();
        var registry = SiemRegistryKeys.Where(k => RegistryHelper.KeyExists(k.KeyPath)).Select(k => k.KeyPath).ToList();

        var targets = RegistryHelper.GetValueNames(WefSubscriptionManagerKey)
            .Select(name => $"{name} = {RegistryHelper.GetValue<string>(WefSubscriptionManagerKey, name, null) ?? "(null)"}")
            .ToList();

        int onboarding = RegistryHelper.GetValue(MdeStatusKey, "OnboardingState", -1);

        return new SiemSnapshot
        {
            Services = services,
            ServiceEnumerationError = serviceError,
            RegistryKeysPresent = registry,
            ForwardingTargets = targets,
            CollectorSubscriptions = RegistryHelper.GetSubKeyNames(CollectorSubscriptionsKey),
            MdeOnboardingState = onboarding < 0 ? null : onboarding,
        };
    }
}

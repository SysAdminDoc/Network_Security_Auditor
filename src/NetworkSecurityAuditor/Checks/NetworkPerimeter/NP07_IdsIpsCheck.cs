namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.ServiceProcess;
using System.Text;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP07 - IDS/IPS: looks for a running IDS/IPS or EDR agent on this host. A host scan can't see an
/// IDS/IPS at the network perimeter, so finding none is Partial, not Fail. The PowerShell NP07 block
/// uses the same service list and the same rules.
/// </summary>
public sealed class NP07_IdsIpsCheck : ISecurityCheck
{
    public string Id => "NP07";

    /// <summary>
    /// Agent services by name; a trailing * is a prefix match. Matching is on the service name only:
    /// a substring match on "bro" (Bro/Zeek) used to hit BrokerInfrastructure on every Windows host.
    /// </summary>
    internal static readonly (string Pattern, string Label)[] AgentServices =
    [
        ("Snort*", "Snort IDS"),
        ("Suricata*", "Suricata IDS"),
        ("OssecSvc", "OSSEC HIDS"),
        ("WazuhSvc", "Wazuh HIDS"),
        ("ds_agent", "Trend Micro Deep Security"),
        ("Sense", "Defender for Endpoint"),
        ("CbDefense", "Carbon Black Cloud"),
        ("CarbonBlack", "Carbon Black EDR"),
        ("CSFalconService", "CrowdStrike Falcon"),
        ("SentinelAgent", "SentinelOne"),
        ("SAVService", "Sophos"),
        ("Sophos Endpoint Defense Service", "Sophos"),
        ("SepMasterService", "Symantec/Broadcom"),
    ];

    /// <summary>Install keys. They outlive uninstalls, so a key without a running agent is listed, not counted.</summary>
    internal static readonly (string KeyPath, string Label)[] TraceKeys =
    [
        (@"HKLM\SOFTWARE\Snort", "Snort"),
        (@"HKLM\SOFTWARE\OISF\Suricata", "Suricata"),
        (@"HKLM\SOFTWARE\OSSEC", "OSSEC"),
        (@"HKLM\SOFTWARE\Wazuh", "Wazuh"),
        (@"HKLM\SOFTWARE\AlienVault", "AlienVault OSSIM"),
        (@"HKLM\SOFTWARE\Trend Micro\Deep Security Agent", "Trend Micro Deep Security"),
        (@"HKLM\SOFTWARE\McAfee\NSP", "McAfee Network Security"),
    ];

    internal sealed record AgentService(string Name, string DisplayName, string State, string Label);

    internal sealed record IdsSnapshot
    {
        public IReadOnlyList<AgentService> Services { get; init; } = [];
        public string? ServiceError { get; init; }
        public int? MdeOnboardingState { get; init; }
        public bool? NisEnabled { get; init; }
        public IReadOnlyList<string> TraceLabels { get; init; } = [];
        public bool IpsecRules { get; init; }
    }

    internal static bool NameMatches(string pattern, string serviceName) =>
        pattern.EndsWith('*')
            ? serviceName.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
            : serviceName.Equals(pattern, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// An agent counts only when its service is running. Defender for Endpoint also needs
    /// OnboardingState 1, because the Sense service ships with every Windows 10/11 and Server 2019+ host.
    /// </summary>
    internal static (bool Counted, string Reason) Counts(AgentService service, int? mdeOnboardingState)
    {
        if (!service.State.Equals("Running", StringComparison.OrdinalIgnoreCase))
            return (false, "not running");
        if (service.Name.Equals("Sense", StringComparison.OrdinalIgnoreCase) && mdeOnboardingState != 1)
            return (false, $"not onboarded (OnboardingState {mdeOnboardingState?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "absent"})");
        return (true, "");
    }

    internal static CheckResult Assess(IdsSnapshot snapshot)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        var counted = new List<string>();

        evidence.AppendLine("[IDS/IPS and EDR agent services]");
        if (snapshot.ServiceError is not null)
            evidence.AppendLine($"  Services couldn't be listed: {snapshot.ServiceError}");
        foreach (var service in snapshot.Services)
        {
            var (isCounted, reason) = Counts(service, snapshot.MdeOnboardingState);
            if (isCounted)
            {
                counted.Add($"{service.Label}: {service.DisplayName}");
                evidence.AppendLine($"  FOUND: {service.Label}: {service.DisplayName} ({service.Name}) - {service.State}");
            }
            else
            {
                evidence.AppendLine($"  Not counted: {service.Label}: {service.DisplayName} ({service.Name}) - {service.State}, {reason}");
            }
        }
        if (snapshot.Services.Count == 0 && snapshot.ServiceError is null)
            evidence.AppendLine("  None installed.");

        evidence.AppendLine("\n[Install traces]");
        foreach (var label in snapshot.TraceLabels)
            evidence.AppendLine($"  {label} registry key present");
        if (snapshot.TraceLabels.Count == 0)
            evidence.AppendLine("  None.");

        evidence.AppendLine("\n[Windows Defender Network Inspection]");
        evidence.AppendLine($"  NIS Enabled: {snapshot.NisEnabled?.ToString() ?? "couldn't be read"}");
        evidence.AppendLine("\n[Windows Firewall IPsec]");
        evidence.AppendLine($"  IPsec connection security rules configured: {snapshot.IpsecRules}");

        CheckStatus status;
        if (counted.Count > 0)
        {
            status = CheckStatus.Pass;
            sb.AppendLine("IDS/IPS or EDR agent running on this host:");
            foreach (var agent in counted)
                sb.AppendLine($"  {agent}");
        }
        else
        {
            status = CheckStatus.Partial;
            sb.AppendLine(snapshot.ServiceError is null
                ? "No running IDS/IPS or EDR agent on this host."
                : "Services couldn't be listed, so a running IDS/IPS or EDR agent couldn't be confirmed.");
            var notCounted = snapshot.Services.Where(s => !Counts(s, snapshot.MdeOnboardingState).Counted).ToList();
            if (notCounted.Count > 0)
                sb.AppendLine($"Installed but not counted: {string.Join(", ", notCounted.Select(s => $"{s.Label} ({Counts(s, snapshot.MdeOnboardingState).Reason})"))}.");
            if (snapshot.TraceLabels.Count > 0)
                sb.AppendLine($"Install traces without a running agent: {string.Join(", ", snapshot.TraceLabels)}.");
            sb.AppendLine("An IDS/IPS at the network perimeter (firewall/UTM) won't show up in a host scan. Confirm it on the network side, " +
                "or deploy a host-based IPS (an EDR with IPS capabilities).");
        }
        if (snapshot.NisEnabled == true)
            sb.AppendLine("Defender Network Inspection System is on. It inspects this host's traffic for known exploits, but it isn't a network IDS/IPS.");
        if (snapshot.IpsecRules)
            sb.AppendLine("INFO: IPsec connection security rules are configured.");

        return new CheckResult
        {
            Status = status,
            Findings = sb.ToString().TrimEnd(),
            Evidence = evidence.ToString().TrimEnd(),
        };
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(Assess(Collect(ct)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static IdsSnapshot Collect(CancellationToken ct)
    {
        var services = new List<AgentService>();
        string? serviceError = null;
        try
        {
            var all = ServiceController.GetServices();
            try
            {
                foreach (var service in all)
                {
                    ct.ThrowIfCancellationRequested();
                    var match = AgentServices.FirstOrDefault(a => NameMatches(a.Pattern, service.ServiceName));
                    if (match.Pattern is null) continue;
                    services.Add(new AgentService(service.ServiceName, service.DisplayName, service.Status.ToString(), match.Label));
                }
            }
            finally
            {
                ServiceControllerDisposal.DisposeAll(all);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            serviceError = ex.Message;
        }

        int onboarding = RegistryHelper.GetValue(EP01_AvEdrCheck.MdeStatusKey, "OnboardingState", -1);

        return new IdsSnapshot
        {
            Services = services,
            ServiceError = serviceError,
            MdeOnboardingState = onboarding < 0 ? null : onboarding,
            NisEnabled = ReadNisEnabled(),
            TraceLabels = TraceKeys.Where(k => RegistryHelper.KeyExists(k.KeyPath)).Select(k => k.Label).ToList(),
            IpsecRules = RegistryHelper.KeyExists(@"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules"),
        };
    }

    private static bool? ReadNisEnabled()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT NISEnabled FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                    return obj["NISEnabled"] is true;
            }
        }
        catch (ManagementException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        return null;
    }
}

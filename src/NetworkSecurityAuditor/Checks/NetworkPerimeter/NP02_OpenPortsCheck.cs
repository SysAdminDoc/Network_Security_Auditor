namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Globalization;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP02 - Open Ports Audit: read listening endpoints from the IP Helper API and classify them.
/// Cleartext remote-access and no-auth-by-default database listeners fail. Sensitive services
/// are reviewed. Windows role ports (RPC, NetBIOS, SMB, WinRM) are informational unless a
/// public-profile interface can reach them through an allowing inbound rule.
/// </summary>
public sealed class NP02_OpenPortsCheck : ISecurityCheck
{
    public string Id => "NP02";

    internal enum PortRisk
    {
        /// <summary>Fails whenever it listens beyond loopback.</summary>
        Insecure,
        /// <summary>Partial beyond loopback; fails when exposed to a public-profile network.</summary>
        Review,
        /// <summary>Default Windows role port; informational unless exposed to a public-profile network.</summary>
        DefaultRole,
    }

    private static readonly Dictionary<(string Protocol, int Port), (string Service, PortRisk Risk)> ClassifiedPorts = new()
    {
        { ("TCP", 21), ("FTP", PortRisk.Insecure) },
        { ("TCP", 23), ("Telnet", PortRisk.Insecure) },
        { ("UDP", 69), ("TFTP", PortRisk.Insecure) },
        { ("TCP", 5900), ("VNC", PortRisk.Insecure) },
        { ("TCP", 5901), ("VNC", PortRisk.Insecure) },
        { ("TCP", 5902), ("VNC", PortRisk.Insecure) },
        { ("TCP", 5903), ("VNC", PortRisk.Insecure) },
        { ("TCP", 6379), ("Redis (no auth by default)", PortRisk.Insecure) },
        { ("TCP", 9200), ("Elasticsearch HTTP (no auth by default before 8.0)", PortRisk.Insecure) },
        { ("TCP", 11211), ("Memcached (no auth)", PortRisk.Insecure) },
        { ("UDP", 11211), ("Memcached (no auth)", PortRisk.Insecure) },
        { ("TCP", 27017), ("MongoDB (no auth by default)", PortRisk.Insecure) },
        { ("TCP", 25), ("SMTP", PortRisk.Review) },
        { ("TCP", 110), ("POP3", PortRisk.Review) },
        { ("TCP", 143), ("IMAP", PortRisk.Review) },
        { ("TCP", 1433), ("MSSQL", PortRisk.Review) },
        { ("UDP", 1434), ("MSSQL Browser", PortRisk.Review) },
        { ("TCP", 3306), ("MySQL", PortRisk.Review) },
        { ("TCP", 3389), ("RDP", PortRisk.Review) },
        { ("TCP", 5432), ("PostgreSQL", PortRisk.Review) },
        { ("TCP", 8080), ("HTTP Proxy/Alt", PortRisk.Review) },
        { ("TCP", 8443), ("HTTPS Alt", PortRisk.Review) },
        { ("TCP", 135), ("RPC/DCOM", PortRisk.DefaultRole) },
        { ("TCP", 139), ("NetBIOS Session", PortRisk.DefaultRole) },
        { ("TCP", 445), ("SMB", PortRisk.DefaultRole) },
        { ("TCP", 5985), ("WinRM HTTP", PortRisk.DefaultRole) },
        { ("TCP", 5986), ("WinRM HTTPS", PortRisk.DefaultRole) },
    };

    internal sealed record ListenerEndpoint(string Protocol, string Address, int Port);

    /// <summary>Everything NP02 reads from the host, so the decision can be tested with fixtures.</summary>
    internal sealed record PortSnapshot
    {
        public IReadOnlyList<ListenerEndpoint> Listeners { get; init; } = [];
        public string? ListenerError { get; init; }
        /// <summary>Unicast addresses on interfaces whose network category is Public.</summary>
        public IReadOnlyList<string> PublicInterfaceAddresses { get; init; } = [];
        /// <summary>Null when the public firewall profile couldn't be read.</summary>
        public bool? PublicFirewallEnabled { get; init; }
        public bool PublicDefaultInboundAllow { get; init; }
        public IReadOnlyList<FirewallRuleSnapshot> FirewallRules { get; init; } = [];
        public string? FirewallError { get; init; }
    }

    internal sealed record PortAssessment(CheckStatus Status, string Findings, string Evidence, string? Error);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var assessment = Assess(CollectSnapshot(ct));
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

    internal static PortAssessment Assess(PortSnapshot snapshot)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();

        evidence.AppendLine("[Listening Endpoints (IP Helper API)]");
        if (snapshot.ListenerError is not null)
        {
            evidence.AppendLine($"  Error reading listeners: {snapshot.ListenerError}");
            return new PortAssessment(
                CheckStatus.NotAssessed,
                "NOT ASSESSED: listening endpoints couldn't be read.",
                evidence.ToString().TrimEnd(),
                snapshot.ListenerError);
        }

        var tcp = snapshot.Listeners.Where(l => l.Protocol == "TCP").ToList();
        foreach (var listener in tcp.OrderBy(l => l.Port).ThenBy(l => l.Address, StringComparer.Ordinal))
            evidence.AppendLine($"  TCP {FormatEndpoint(listener)}");

        evidence.AppendLine("\n[Public Network Exposure]");
        evidence.AppendLine(snapshot.PublicInterfaceAddresses.Count == 0
            ? "  No interface is on a Public network profile."
            : $"  Public-profile addresses: {string.Join(", ", snapshot.PublicInterfaceAddresses)}");
        if (snapshot.FirewallError is not null)
            evidence.AppendLine($"  Firewall rules couldn't be read ({snapshot.FirewallError}); public exposure isn't assumed.");
        else
            evidence.AppendLine($"  Public firewall profile: {(snapshot.PublicFirewallEnabled switch { true => "On", false => "OFF", null => "unknown" })}" +
                (snapshot.PublicDefaultInboundAllow ? ", default inbound ALLOW" : string.Empty));

        var failures = new List<string>();
        var reviews = new List<string>();
        var informational = new List<string>();

        var classified = snapshot.Listeners
            .Where(l => ClassifiedPorts.ContainsKey((l.Protocol, l.Port)))
            .GroupBy(l => (l.Protocol, l.Port))
            .OrderBy(g => g.Key.Port);
        foreach (var group in classified)
        {
            var (service, risk) = ClassifiedPorts[group.Key];
            var reachable = group.Where(l => !IsLoopback(l.Address)).ToList();
            string label = $"{group.Key.Protocol} {group.Key.Port} ({service})";
            if (reachable.Count == 0)
            {
                informational.Add($"{label} on loopback only");
                continue;
            }

            string binds = string.Join(", ", reachable.Select(l => DescribeBind(l.Address)).Distinct());
            var exposingRule = FindPublicExposure(snapshot, reachable);
            bool exposureUnknown = exposingRule is null && snapshot.FirewallError is not null && BindsToPublicInterface(snapshot, reachable);
            if (risk == PortRisk.Insecure)
            {
                failures.Add($"{label} listening on {binds}{(exposingRule is null ? string.Empty : $"; public exposure via {exposingRule}")}");
            }
            else if (exposingRule is not null)
            {
                failures.Add($"{label} reachable from a Public-profile network via {exposingRule} ({binds})");
            }
            else if (exposureUnknown)
            {
                reviews.Add($"{label} on {binds} is bound to a Public-profile interface, and the firewall couldn't be read to confirm it's blocked");
            }
            else if (risk == PortRisk.Review)
            {
                reviews.Add($"{label} listening on {binds}");
            }
            else
            {
                informational.Add($"{label} on {binds}; default Windows role port, not exposed to a Public-profile network");
            }
        }

        int reachableTcp = tcp.Count(l => !IsLoopback(l.Address));
        sb.AppendLine($"Listening TCP endpoints: {tcp.Count} ({reachableTcp} beyond loopback).");

        if (failures.Count > 0)
        {
            sb.AppendLine($"\nFAIL: {failures.Count} high-risk listener(s):");
            foreach (var item in failures) sb.AppendLine($"  {item}");
        }
        if (reviews.Count > 0)
        {
            sb.AppendLine($"\nREVIEW: {reviews.Count} sensitive service(s) listening beyond loopback:");
            foreach (var item in reviews) sb.AppendLine($"  {item}");
        }
        if (informational.Count > 0)
        {
            sb.AppendLine("\nInformational:");
            foreach (var item in informational) sb.AppendLine($"  {item}");
        }
        if (failures.Count > 0 || reviews.Count > 0)
        {
            sb.AppendLine("\nRecommendation: Disable services that aren't needed, restrict the rest with firewall rules scoped to trusted networks, " +
                "and replace cleartext protocols (SFTP instead of FTP, SSH instead of Telnet). Require authentication on database listeners.");
        }
        else
        {
            sb.AppendLine("PASS: No high-risk listeners, and no default role port is exposed to a Public-profile network.");
        }

        if (reachableTcp > 30)
            sb.AppendLine($"WARNING: {reachableTcp} TCP listeners beyond loopback is a large attack surface. Review for unnecessary services.");

        var status = failures.Count > 0 ? CheckStatus.Fail
            : reviews.Count > 0 ? CheckStatus.Partial
            : CheckStatus.Pass;
        return new PortAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd(), null);
    }

    /// <summary>
    /// Returns a description of what exposes the listeners to a Public-profile network, or null.
    /// Program-scoped rules without a port aren't mapped, because listener ownership isn't read.
    /// </summary>
    private static string? FindPublicExposure(PortSnapshot snapshot, IReadOnlyList<ListenerEndpoint> reachable)
    {
        if (snapshot.FirewallError is not null)
            return null;
        var publicBinds = PublicBinds(snapshot, reachable);
        if (publicBinds.Count == 0)
            return null;
        if (snapshot.PublicFirewallEnabled == false)
            return "the Public firewall profile being off";
        if (snapshot.PublicDefaultInboundAllow)
            return "the Public profile's default inbound Allow";

        // A rule naming the port counts whatever program it names (SMB-In is scoped to System).
        // An any-port rule counts only when it isn't scoped to a program.
        var endpoint = publicBinds[0];
        var rule = snapshot.FirewallRules.FirstOrDefault(r =>
            r.IsInbound && r.IsAllow && r.AppliesToPublicProfile &&
            ProtocolMatches(r.Protocol, endpoint.Protocol) &&
            (r.HasAnyLocalPort ? r.HasAnyProgram : LocalPortsInclude(r.LocalPorts, endpoint.Port)));
        return rule is null ? null : $"inbound rule '{rule.Name}'";
    }

    private static List<ListenerEndpoint> PublicBinds(PortSnapshot snapshot, IReadOnlyList<ListenerEndpoint> reachable) =>
        snapshot.PublicInterfaceAddresses.Count == 0
            ? []
            : reachable.Where(l => IsWildcard(l.Address) ||
                snapshot.PublicInterfaceAddresses.Any(a => SameAddress(a, l.Address))).ToList();

    private static bool BindsToPublicInterface(PortSnapshot snapshot, IReadOnlyList<ListenerEndpoint> reachable) =>
        PublicBinds(snapshot, reachable).Count > 0;

    internal static bool LocalPortsInclude(IEnumerable<string> localPorts, int port)
    {
        foreach (var raw in localPorts)
        {
            var value = raw.Trim();
            if (value.Equals("RPC-EPMap", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("RPCEPMap", StringComparison.OrdinalIgnoreCase))
            {
                if (port == 135) return true;
                continue;
            }
            var dash = value.IndexOf('-');
            if (dash > 0 &&
                int.TryParse(value[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out var low) &&
                int.TryParse(value[(dash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var high))
            {
                if (port >= low && port <= high) return true;
                continue;
            }
            if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var single) && single == port)
                return true;
        }
        return false;
    }

    private static bool ProtocolMatches(string? ruleProtocol, string listenerProtocol)
    {
        if (string.IsNullOrWhiteSpace(ruleProtocol) || ruleProtocol.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return true;
        return listenerProtocol switch
        {
            "TCP" => ruleProtocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) || ruleProtocol == "6",
            "UDP" => ruleProtocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) || ruleProtocol == "17",
            _ => false,
        };
    }

    private static string StripScope(string address)
    {
        var percent = address.IndexOf('%');
        return percent < 0 ? address : address[..percent];
    }

    private static bool SameAddress(string left, string right) =>
        IPAddress.TryParse(StripScope(left), out var a) && IPAddress.TryParse(StripScope(right), out var b) && a.Equals(b);

    private static bool IsWildcard(string address) =>
        IPAddress.TryParse(StripScope(address), out var ip) && (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any));

    private static bool IsLoopback(string address) =>
        IPAddress.TryParse(StripScope(address), out var ip) && IPAddress.IsLoopback(ip);

    private static string DescribeBind(string address) => IsWildcard(address) ? $"{address} (all interfaces)" : address;

    private static string FormatEndpoint(ListenerEndpoint listener) =>
        listener.Address.Contains(':') ? $"[{listener.Address}]:{listener.Port}" : $"{listener.Address}:{listener.Port}";

    private static PortSnapshot CollectSnapshot(CancellationToken ct)
    {
        List<ListenerEndpoint> listeners;
        string? listenerError = null;
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            listeners = properties.GetActiveTcpListeners()
                .Select(e => new ListenerEndpoint("TCP", e.Address.ToString(), e.Port))
                .Concat(properties.GetActiveUdpListeners()
                    .Where(e => ClassifiedPorts.ContainsKey(("UDP", e.Port)))
                    .Select(e => new ListenerEndpoint("UDP", e.Address.ToString(), e.Port)))
                .Distinct()
                .ToList();
        }
        catch (Exception ex) when (ex is NetworkInformationException or InvalidOperationException or PlatformNotSupportedException)
        {
            listeners = [];
            listenerError = ex.Message;
        }

        ct.ThrowIfCancellationRequested();
        var publicAddresses = new List<string>();
        bool? firewallEnabled = null;
        bool defaultAllow = false;
        IReadOnlyList<FirewallRuleSnapshot> rules = [];
        string? firewallError = null;
        try
        {
            var publicIndexes = ReadPublicInterfaceIndexes();
            if (publicIndexes.Count > 0)
            {
                publicAddresses = ReadInterfaceAddresses(publicIndexes);
                (firewallEnabled, defaultAllow) = ReadPublicFirewallProfile();
                rules = FirewallRuleReader.GetEnabledRules(ct)
                    .Where(r => r.IsInbound && r.IsAllow && r.AppliesToPublicProfile)
                    .ToList();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            firewallError = ex.Message;
        }

        return new PortSnapshot
        {
            Listeners = listeners,
            ListenerError = listenerError,
            PublicInterfaceAddresses = publicAddresses,
            PublicFirewallEnabled = firewallEnabled,
            PublicDefaultInboundAllow = defaultAllow,
            FirewallRules = rules,
            FirewallError = firewallError,
        };
    }

    private static HashSet<int> ReadPublicInterfaceIndexes()
    {
        var indexes = new HashSet<int>();
        using var searcher = new ManagementObjectSearcher(
            @"root\StandardCimv2", "SELECT InterfaceIndex, NetworkCategory FROM MSFT_NetConnectionProfile");
        using var results = searcher.Get();
        foreach (ManagementObject profile in results)
        {
            using (profile)
            {
                // NetworkCategory: 0 = Public, 1 = Private, 2 = DomainAuthenticated.
                if (Convert.ToInt32(profile["NetworkCategory"] ?? -1, CultureInfo.InvariantCulture) == 0)
                    indexes.Add(Convert.ToInt32(profile["InterfaceIndex"] ?? -1, CultureInfo.InvariantCulture));
            }
        }
        return indexes;
    }

    private static List<string> ReadInterfaceAddresses(HashSet<int> indexes)
    {
        var addresses = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            int? v4 = null, v6 = null;
            try { v4 = props.GetIPv4Properties()?.Index; } catch (NetworkInformationException) { }
            try { v6 = props.GetIPv6Properties()?.Index; } catch (NetworkInformationException) { }
            if (!(v4 is int i4 && indexes.Contains(i4)) && !(v6 is int i6 && indexes.Contains(i6)))
                continue;
            addresses.AddRange(props.UnicastAddresses.Select(u => StripScope(u.Address.ToString())));
        }
        return addresses.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static (bool? Enabled, bool DefaultInboundAllow) ReadPublicFirewallProfile()
    {
        using var searcher = new ManagementObjectSearcher(
            @"root\StandardCimv2", "SELECT Name, Enabled, DefaultInboundAction FROM MSFT_NetFirewallProfile WHERE Name = 'Public'");
        using var results = searcher.Get();
        foreach (ManagementObject profile in results)
        {
            using (profile)
            {
                // Enabled: 0 = False, 1 = True, 2 = NotConfigured (on). DefaultInboundAction: 2 = Allow.
                int enabled = Convert.ToInt32(profile["Enabled"] ?? 1, CultureInfo.InvariantCulture);
                int inbound = Convert.ToInt32(profile["DefaultInboundAction"] ?? 0, CultureInfo.InvariantCulture);
                return (enabled != 0, inbound == 2);
            }
        }
        return (null, false);
    }
}

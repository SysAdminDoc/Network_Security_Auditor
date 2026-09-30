namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;

internal sealed record FirewallRuleSnapshot(
    string InstanceId,
    string Name,
    string Description,
    int Direction,
    int Action,
    string? Protocol,
    string[] LocalPorts,
    string[] RemotePorts,
    string[] RemoteAddresses,
    int Profiles = 0,
    string? Program = null,
    string? Package = null,
    string? Service = null,
    string? Owner = null)
{
    public bool IsInbound => Direction == 1;
    public bool IsOutbound => Direction == 2;
    public bool IsAllow => Action == 2;
    public bool IsBlock => Action == 4;
    public bool HasAnyLocalPort => FirewallRuleReader.IsAnyValue(LocalPorts);
    public bool HasAnyRemotePort => FirewallRuleReader.IsAnyValue(RemotePorts);
    public bool HasAnyRemoteAddress => FirewallRuleReader.IsAnyValue(RemoteAddresses);
    // MSFT_NetFirewallRule.Profiles: 0 = Any, 1 = Domain, 2 = Private, 4 = Public.
    public bool AppliesToPublicProfile => Profiles == 0 || (Profiles & 4) != 0;
    /// <summary>
    /// True when the rule isn't narrowed to a program, an AppContainer package, a service or a
    /// per-user owner, so an any-port rule really opens every port.
    /// </summary>
    public bool HasNoApplicationScope =>
        FirewallRuleReader.IsUnscoped(Program) && FirewallRuleReader.IsUnscoped(Package) &&
        FirewallRuleReader.IsUnscoped(Service) && FirewallRuleReader.IsUnscoped(Owner);
}

internal static class FirewallRuleReader
{
    private const string NamespacePath = @"root\StandardCimv2";

    internal const string RuleQuery =
        "SELECT InstanceID, ElementName, Description, Direction, Action, Enabled, Profiles, Owner, " +
        "CreationClassName, PolicyRuleName, SystemCreationClassName, SystemName " +
        "FROM MSFT_NetFirewallRule WHERE Enabled = 1";
    internal const string PortFilterQuery = "SELECT InstanceID, Protocol, LocalPort, RemotePort FROM MSFT_NetProtocolPortFilter";
    internal const string AddressFilterQuery = "SELECT InstanceID, RemoteAddress FROM MSFT_NetAddressFilter";
    internal const string ApplicationFilterQuery = "SELECT InstanceID, AppPath, Package FROM MSFT_NetApplicationFilter";
    internal const string ServiceFilterQuery = "SELECT InstanceID, ServiceName FROM MSFT_NetServiceFilter";

    internal static readonly string[] Queries = [RuleQuery, PortFilterQuery, AddressFilterQuery, ApplicationFilterQuery, ServiceFilterQuery];
    /// <summary>The store Get-NetFirewallRule -PolicyStore ActiveStore reads: local and Group Policy rules merged.</summary>
    public const string ActiveStore = "ActiveStore";

    /// <summary>
    /// Reads enabled rules. With <paramref name="policyStore"/> null the provider's default
    /// (local persistent) store is used; pass <see cref="ActiveStore"/> to include Group Policy rules.
    /// </summary>
    public static IReadOnlyList<FirewallRuleSnapshot> GetEnabledRules(CancellationToken ct, string? policyStore = null)
    {
        using var searcher = CreateSearcher(RuleQuery, policyStore);

        var rules = new List<FirewallRuleSnapshot>();
        var portFilters = LoadProtocolPortFilters(ct, policyStore);
        var addressFilters = LoadAddressFilters(ct, policyStore);
        var applicationFilters = LoadApplicationFilters(ct, policyStore);
        var serviceFilters = LoadServiceFilters(ct, policyStore);

        using var results = searcher.Get();
        foreach (ManagementObject rule in results)
        {
            using (rule)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(rule["InstanceID"], string.Empty);
                portFilters.TryGetValue(instanceId, out var protocolFilter);
                addressFilters.TryGetValue(instanceId, out var addressFilter);
                applicationFilters.TryGetValue(instanceId, out var applicationFilter);
                serviceFilters.TryGetValue(instanceId, out var service);

                rules.Add(new FirewallRuleSnapshot(
                    instanceId,
                    GetString(rule["ElementName"], GetString(rule["InstanceID"], "Unknown")),
                    GetString(rule["Description"], string.Empty),
                    GetInt(rule["Direction"]),
                    GetInt(rule["Action"]),
                    protocolFilter?.Protocol,
                    protocolFilter?.LocalPorts ?? [],
                    protocolFilter?.RemotePorts ?? [],
                    addressFilter?.RemoteAddresses ?? [],
                    GetInt(rule["Profiles"]),
                    applicationFilter?.AppPath,
                    applicationFilter?.Package,
                    service,
                    GetString(rule["Owner"], null)));
            }
        }

        return rules;
    }

    public static bool IsAnyValue(IEnumerable<string> values)
    {
        var seen = false;

        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value)) continue;

            seen = true;
            var trimmed = value.Trim();
            if (trimmed.Equals("Any", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("*", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("0.0.0.0/0", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("::/0", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return !seen;
    }

    internal static bool IsUnscoped(string? value) =>
        string.IsNullOrWhiteSpace(value) ||
        value.Trim().Equals("Any", StringComparison.OrdinalIgnoreCase) ||
        value.Trim().Equals("*", StringComparison.Ordinal);

    public static string FormatValues(IEnumerable<string> values)
    {
        var filtered = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .ToArray();

        return filtered.Length == 0 ? "Any" : string.Join(",", filtered);
    }

    /// <summary>
    /// Builds a searcher on root\StandardCimv2. The NetSecurity provider reads the WMI context value
    /// PolicyStore the same way it reads the -PolicyStore operation option from PowerShell.
    /// </summary>
    internal static ManagementObjectSearcher CreateSearcher(string query, string? policyStore)
    {
        var options = new EnumerationOptions();
        if (!string.IsNullOrWhiteSpace(policyStore))
            options.Context = new ManagementNamedValueCollection { { "PolicyStore", policyStore } };
        return new ManagementObjectSearcher(new ManagementScope(NamespacePath), new ObjectQuery(query), options);
    }

    private static Dictionary<string, ProtocolPortFilter> LoadProtocolPortFilters(CancellationToken ct, string? policyStore)
    {
        using var searcher = CreateSearcher(PortFilterQuery, policyStore);

        var filters = new Dictionary<string, ProtocolPortFilter>(StringComparer.OrdinalIgnoreCase);
        using var results = searcher.Get();
        foreach (ManagementObject filter in results)
        {
            using (filter)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(filter["InstanceID"], string.Empty);
                if (string.IsNullOrWhiteSpace(instanceId)) continue;

                filters[instanceId] = new ProtocolPortFilter(
                    GetString(filter["Protocol"], null),
                    GetStringArray(filter["LocalPort"]),
                    GetStringArray(filter["RemotePort"]));
            }
        }

        return filters;
    }

    private static Dictionary<string, AddressFilter> LoadAddressFilters(CancellationToken ct, string? policyStore)
    {
        using var searcher = CreateSearcher(AddressFilterQuery, policyStore);

        var filters = new Dictionary<string, AddressFilter>(StringComparer.OrdinalIgnoreCase);
        using var results = searcher.Get();
        foreach (ManagementObject filter in results)
        {
            using (filter)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(filter["InstanceID"], string.Empty);
                if (string.IsNullOrWhiteSpace(instanceId)) continue;

                filters[instanceId] = new AddressFilter(GetStringArray(filter["RemoteAddress"]));
            }
        }

        return filters;
    }

    // MSFT_NetApplicationFilter exposes AppPath and Package (PowerShell shows AppPath as Program).
    private static Dictionary<string, ApplicationFilter> LoadApplicationFilters(CancellationToken ct, string? policyStore)
    {
        using var searcher = CreateSearcher(ApplicationFilterQuery, policyStore);

        var filters = new Dictionary<string, ApplicationFilter>(StringComparer.OrdinalIgnoreCase);
        using var results = searcher.Get();
        foreach (ManagementObject filter in results)
        {
            using (filter)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(filter["InstanceID"], string.Empty);
                if (string.IsNullOrWhiteSpace(instanceId)) continue;

                filters[instanceId] = new ApplicationFilter(GetString(filter["AppPath"], null), GetString(filter["Package"], null));
            }
        }

        return filters;
    }

    private static Dictionary<string, string> LoadServiceFilters(CancellationToken ct, string? policyStore)
    {
        using var searcher = CreateSearcher(ServiceFilterQuery, policyStore);

        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var results = searcher.Get();
        foreach (ManagementObject filter in results)
        {
            using (filter)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(filter["InstanceID"], string.Empty);
                if (string.IsNullOrWhiteSpace(instanceId)) continue;

                filters[instanceId] = GetString(filter["ServiceName"], "Any");
            }
        }

        return filters;
    }

    private static string GetString(object? value, string? fallback)
    {
        return string.IsNullOrWhiteSpace(value?.ToString()) ? fallback ?? string.Empty : value.ToString()!;
    }

    private static int GetInt(object? value)
    {
        return value is null ? 0 : Convert.ToInt32(value);
    }

    private static string[] GetStringArray(object? value)
    {
        return value switch
        {
            null => [],
            string single when string.IsNullOrWhiteSpace(single) => [],
            string single => [single],
            string[] array => array.Where(item => !string.IsNullOrWhiteSpace(item)).ToArray(),
            Array array => array
                .Cast<object?>()
                .Select(item => item?.ToString())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item!)
                .ToArray(),
            _ => [value.ToString() ?? string.Empty],
        };
    }

    private sealed record ProtocolPortFilter(string? Protocol, string[] LocalPorts, string[] RemotePorts);

    private sealed record AddressFilter(string[] RemoteAddresses);

    private sealed record ApplicationFilter(string? AppPath, string? Package);
}

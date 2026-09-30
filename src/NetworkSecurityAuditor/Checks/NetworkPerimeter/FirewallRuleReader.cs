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
    string? Program = null)
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
    public bool HasAnyProgram => string.IsNullOrWhiteSpace(Program) ||
        Program.Trim().Equals("Any", StringComparison.OrdinalIgnoreCase);
}

internal static class FirewallRuleReader
{
    private const string NamespacePath = @"root\StandardCimv2";

    public static IReadOnlyList<FirewallRuleSnapshot> GetEnabledRules(CancellationToken ct)
    {
        using var searcher = new ManagementObjectSearcher(
            NamespacePath,
            "SELECT InstanceID, ElementName, Description, Direction, Action, Enabled, Profiles, " +
            "CreationClassName, PolicyRuleName, SystemCreationClassName, SystemName " +
            "FROM MSFT_NetFirewallRule WHERE Enabled = 1");

        var rules = new List<FirewallRuleSnapshot>();
        var portFilters = LoadProtocolPortFilters(ct);
        var addressFilters = LoadAddressFilters(ct);
        var programs = LoadApplicationFilters(ct);

        using var results = searcher.Get();
        foreach (ManagementObject rule in results)
        {
            using (rule)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(rule["InstanceID"], string.Empty);
                portFilters.TryGetValue(instanceId, out var protocolFilter);
                addressFilters.TryGetValue(instanceId, out var addressFilter);
                programs.TryGetValue(instanceId, out var program);

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
                    program));
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

    public static string FormatValues(IEnumerable<string> values)
    {
        var filtered = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .ToArray();

        return filtered.Length == 0 ? "Any" : string.Join(",", filtered);
    }

    private static Dictionary<string, ProtocolPortFilter> LoadProtocolPortFilters(CancellationToken ct)
    {
        using var searcher = new ManagementObjectSearcher(
            NamespacePath,
            "SELECT InstanceID, Protocol, LocalPort, RemotePort FROM MSFT_NetProtocolPortFilter");

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

    private static Dictionary<string, AddressFilter> LoadAddressFilters(CancellationToken ct)
    {
        using var searcher = new ManagementObjectSearcher(
            NamespacePath,
            "SELECT InstanceID, RemoteAddress FROM MSFT_NetAddressFilter");

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

    private static Dictionary<string, string> LoadApplicationFilters(CancellationToken ct)
    {
        using var searcher = new ManagementObjectSearcher(
            NamespacePath,
            "SELECT InstanceID, Program FROM MSFT_NetApplicationFilter");

        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var results = searcher.Get();
        foreach (ManagementObject filter in results)
        {
            using (filter)
            {
                ct.ThrowIfCancellationRequested();

                var instanceId = GetString(filter["InstanceID"], string.Empty);
                if (string.IsNullOrWhiteSpace(instanceId)) continue;

                filters[instanceId] = GetString(filter["Program"], "Any");
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
}

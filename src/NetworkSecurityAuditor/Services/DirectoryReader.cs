using System.DirectoryServices;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using NetworkSecurityAuditor.Checks.IdentityAccess;

namespace NetworkSecurityAuditor.Services;

/// <summary>
/// The directory reads the AD checks make: searches, single-object attribute reads (the domain root,
/// RootDSE, a member DN) and access rules. Tests swap in a fixture-backed reader.
/// </summary>
public interface IDirectoryReader
{
    /// <summary>Runs a paged search. A <see cref="DirectoryQuery.SizeLimit"/> of 1 is a FindOne.</summary>
    IReadOnlyList<DirectoryRecord> Search(DirectoryQuery query, CancellationToken ct);

    /// <summary>
    /// Reads attributes of one object. A null DN is the domain root; <see cref="DirectoryReader.RootDse"/> is RootDSE.
    /// Throws the provider's exception when the object doesn't exist or can't be read.
    /// </summary>
    DirectoryRecord ReadEntry(string? distinguishedName, IReadOnlyList<string> properties, CancellationToken ct);

    /// <summary>Reads the explicit and inherited access rules on one object, with identities as NT account names.</summary>
    IReadOnlyList<DirectoryAccessRule> ReadAccessRules(string distinguishedName, CancellationToken ct);
}

public static class DirectoryReader
{
    public const string RootDse = "RootDSE";

    /// <summary>Forward slashes in DN components must be escaped for an ADsPath.</summary>
    public static string EscapeDn(string dn) => dn.Replace("/", "\\/");
}

/// <summary>A search, described so a fixture can answer it. Null <see cref="SearchBase"/> searches the domain root.</summary>
public sealed record DirectoryQuery(string Filter, IReadOnlyList<string> Properties)
{
    public string? SearchBase { get; init; }
    public SearchScope Scope { get; init; } = SearchScope.Subtree;
    public int SizeLimit { get; init; }
    public int PageSize { get; init; } = 1000;
}

public sealed record DirectoryAccessRule(
    string Identity,
    ActiveDirectoryRights Rights,
    AccessControlType Type,
    Guid ObjectType,
    bool IsInherited);

/// <summary>
/// One directory object's attributes, matched case-insensitively. Integer8 values arrive as <see cref="long"/>
/// from a search and as a COM large integer from an entry read; the accessors accept both.
/// </summary>
public sealed class DirectoryRecord
{
    private readonly Dictionary<string, IReadOnlyList<object>> _attributes;

    public DirectoryRecord(string path, IReadOnlyDictionary<string, IReadOnlyList<object>> attributes)
    {
        Path = path;
        _attributes = new Dictionary<string, IReadOnlyList<object>>(attributes, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The ADsPath (or DN for a fixture) the record came from.</summary>
    public string Path { get; }

    public IReadOnlyList<object> Values(string name) =>
        _attributes.TryGetValue(name, out var values) ? values : [];

    public bool Has(string name) => Values(name).Count > 0;

    public object? First(string name) => Values(name) is { Count: > 0 } values ? values[0] : null;

    public string? String(string name) => First(name)?.ToString();

    public IReadOnlyList<string> Strings(string name) =>
        Values(name).Select(value => value?.ToString() ?? "").ToArray();

    public int Int(string name, int fallback = 0) => First(name) switch
    {
        int value => value,
        long value when value is >= int.MinValue and <= int.MaxValue => (int)value,
        string text when int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
        _ => fallback
    };

    public long Long(string name) => First(name) switch
    {
        null => 0,
        string text => long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0,
        var value => ActiveDirectoryValueConverter.GetLargeIntegerValue(value)
    };

    public DateTime? FileTimeUtc(string name) => ActiveDirectoryValueConverter.GetFileTimeUtc(First(name));

    public DateTime? Time(string name) => First(name) is DateTime value ? value : null;

    public byte[]? Bytes(string name) => First(name) as byte[];
}

/// <summary>Reads Active Directory over LDAP, bound to the machine's domain.</summary>
public sealed class LdapDirectoryReader(string domainName) : IDirectoryReader
{
    // The domain root and RootDSE bind to the machine's domain. A DN binds serverless, as the checks always
    // did, so a member DN from another domain in the forest still resolves.
    private string Bind(string? distinguishedName)
    {
        var server = string.IsNullOrWhiteSpace(domainName) ? "" : domainName.Trim();
        return distinguishedName switch
        {
            null => "LDAP://" + server,
            DirectoryReader.RootDse => server.Length == 0 ? "LDAP://RootDSE" : $"LDAP://{server}/RootDSE",
            _ => "LDAP://" + DirectoryReader.EscapeDn(distinguishedName)
        };
    }

    public IReadOnlyList<DirectoryRecord> Search(DirectoryQuery query, CancellationToken ct)
    {
        using var root = new DirectoryEntry(Bind(query.SearchBase));
        using var searcher = new DirectorySearcher(root)
        {
            Filter = query.Filter,
            SearchScope = query.Scope,
            PageSize = query.SizeLimit == 1 ? 0 : query.PageSize,
            SizeLimit = query.SizeLimit
        };
        searcher.PropertiesToLoad.AddRange([.. query.Properties]);

        var records = new List<DirectoryRecord>();
        if (query.SizeLimit == 1)
        {
            ct.ThrowIfCancellationRequested();
            if (searcher.FindOne() is { } one)
                records.Add(ToRecord(one));
            return records;
        }

        using var results = searcher.FindAll();
        foreach (SearchResult result in results)
        {
            ct.ThrowIfCancellationRequested();
            records.Add(ToRecord(result));
        }
        return records;
    }

    public DirectoryRecord ReadEntry(string? distinguishedName, IReadOnlyList<string> properties, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var entry = new DirectoryEntry(Bind(distinguishedName));
        entry.RefreshCache([.. properties]);

        var attributes = new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in properties)
        {
            if (entry.Properties[property] is not { Count: > 0 } values)
                continue;
            var list = new List<object>(values.Count);
            foreach (var value in values)
            {
                if (value is not null)
                    list.Add(Normalize(value));
            }
            attributes[property] = list;
        }
        return new DirectoryRecord(entry.Path, attributes);
    }

    public IReadOnlyList<DirectoryAccessRule> ReadAccessRules(string distinguishedName, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var entry = new DirectoryEntry(Bind(distinguishedName));
        entry.RefreshCache(["ntSecurityDescriptor"]);
        var rules = entry.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));

        var result = new List<DirectoryAccessRule>(rules.Count);
        foreach (AuthorizationRule rule in rules)
        {
            if (rule is ActiveDirectoryAccessRule adRule)
            {
                result.Add(new DirectoryAccessRule(
                    adRule.IdentityReference?.Value ?? "Unknown",
                    adRule.ActiveDirectoryRights,
                    adRule.AccessControlType,
                    adRule.ObjectType,
                    adRule.IsInherited));
            }
        }
        return result;
    }

    private static DirectoryRecord ToRecord(SearchResult result)
    {
        var attributes = new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in result.Properties.PropertyNames)
        {
            var values = result.Properties[name];
            var list = new List<object>(values.Count);
            foreach (var value in values)
            {
                if (value is not null)
                    list.Add(value);
            }
            attributes[name] = list;
        }
        return new DirectoryRecord(result.Path, attributes);
    }

    // DirectoryEntry hands Integer8 values back as a COM IADsLargeInteger; a search hands back a long.
    private static object Normalize(object value) =>
        value.GetType().IsCOMObject ? ActiveDirectoryValueConverter.GetLargeIntegerValue(value) : value;
}

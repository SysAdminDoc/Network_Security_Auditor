using System.ComponentModel;
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

    /// <summary>
    /// Reads one object's owner and access rules together. A reader that can't report the owner returns a null
    /// owner and the rules from <see cref="ReadAccessRules"/>.
    /// </summary>
    DirectoryAcl ReadAcl(string distinguishedName, CancellationToken ct) =>
        new(null, null, ReadAccessRules(distinguishedName, ct));
}

/// <summary>An object's owner (SID and display name, null when unknown) and its access rules.</summary>
public sealed record DirectoryAcl(string? OwnerSid, string? Owner, IReadOnlyList<DirectoryAccessRule> Rules);

public static class DirectoryReader
{
    public const string RootDse = "RootDSE";

    /// <summary>
    /// RootDSE bound serverless (<c>LDAP://RootDSE</c>), which follows the signed-in user's own DC. On a
    /// child-domain member where a forest-root admin is signed in, this reads that DC's RootDSE, not the
    /// machine domain's. <see cref="RootDse"/> instead targets the machine's domain by name.
    /// </summary>
    public const string RootDseServerless = "RootDSE:serverless";

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

    /// <summary>
    /// Bind <see cref="SearchBase"/> on the machine domain's server (<c>LDAP://domain/DN</c>) rather than serverless.
    /// A serverless DN goes to the signed-in user's DC, which may be in another forest and not hold this partition.
    /// </summary>
    public bool OnDomainServer { get; init; }
}

/// <summary>
/// One access rule. <see cref="Identity"/> is the account name for display (the SID string when it can't be
/// translated); <see cref="Sid"/> is what checks should compare, since group names are localized.
/// <see cref="InheritOnly"/> rules don't apply to the object itself, only to the children that inherit them.
/// </summary>
public sealed record DirectoryAccessRule(
    string Identity,
    ActiveDirectoryRights Rights,
    AccessControlType Type,
    Guid ObjectType,
    bool IsInherited,
    string? Sid = null,
    bool InheritOnly = false);

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

    /// <summary>A binary SID attribute such as objectSid, in S-1-5-... form.</summary>
    public string? Sid(string name) => Bytes(name) is { } bytes ? new SecurityIdentifier(bytes, 0).Value : null;
}

/// <summary>Reads Active Directory over LDAP, bound to the machine's domain.</summary>
public sealed class LdapDirectoryReader(string domainName) : IDirectoryReader
{
    // The domain root and RootDSE bind to the machine's domain. A DN binds serverless, as the checks always
    // did, so a member DN from another domain in the forest still resolves, unless the caller asks for the
    // domain's server (the schema search, which the old code bound there).
    internal string Bind(string? distinguishedName, bool onDomainServer = false)
    {
        var server = string.IsNullOrWhiteSpace(domainName) ? "" : domainName.Trim();
        return distinguishedName switch
        {
            null => "LDAP://" + server,
            DirectoryReader.RootDseServerless => "LDAP://RootDSE",
            DirectoryReader.RootDse => server.Length == 0 ? "LDAP://RootDSE" : $"LDAP://{server}/RootDSE",
            _ when onDomainServer && server.Length > 0 => $"LDAP://{server}/{DirectoryReader.EscapeDn(distinguishedName)}",
            _ => "LDAP://" + DirectoryReader.EscapeDn(distinguishedName)
        };
    }

    /// <summary>
    /// How long a domain controller may spend on one page of a paged search. When it runs out, the DC returns
    /// that page early with a cookie and the search carries on, so nothing is dropped. ServerTimeLimit and
    /// ClientTimeout stay at their defaults on purpose: when either runs out, the whole search ends with what it
    /// has so far and no error, and a check would score a partial list as complete. A stalled DC is left to the
    /// runner's check timeout, which reports the check as timed out.
    /// </summary>
    internal static readonly TimeSpan SearchServerPageTimeLimit = TimeSpan.FromSeconds(60);

    public IReadOnlyList<DirectoryRecord> Search(DirectoryQuery query, CancellationToken ct)
    {
        using var root = new DirectoryEntry(Bind(query.SearchBase, query.OnDomainServer));
        using var searcher = CreateSearcher(root, query);

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

    /// <summary>Builds the searcher for a query. Creating it doesn't contact a DC.</summary>
    internal static DirectorySearcher CreateSearcher(DirectoryEntry root, DirectoryQuery query)
    {
        var searcher = new DirectorySearcher(root)
        {
            Filter = query.Filter,
            SearchScope = query.Scope,
            PageSize = query.SizeLimit == 1 ? 0 : query.PageSize,
            SizeLimit = query.SizeLimit,
            ServerPageTimeLimit = SearchServerPageTimeLimit
        };
        searcher.PropertiesToLoad.AddRange([.. query.Properties]);
        return searcher;
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
        var rules = entry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<DirectoryAccessRule>(rules.Count);
        foreach (AuthorizationRule rule in rules)
        {
            if (rule is ActiveDirectoryAccessRule adRule && adRule.IdentityReference is SecurityIdentifier sid)
            {
                if (!names.TryGetValue(sid.Value, out var name))
                    names[sid.Value] = name = AccountName(sid);
                result.Add(new DirectoryAccessRule(
                    name,
                    adRule.ActiveDirectoryRights,
                    adRule.AccessControlType,
                    adRule.ObjectType,
                    adRule.IsInherited,
                    sid.Value,
                    adRule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)));
            }
        }
        return result;
    }

    // One bind for the owner and the rules, so a sweep over many OUs doesn't read each descriptor twice.
    public DirectoryAcl ReadAcl(string distinguishedName, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var entry = new DirectoryEntry(Bind(distinguishedName));
        entry.RefreshCache(["ntSecurityDescriptor"]);
        var security = entry.ObjectSecurity;
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string Name(SecurityIdentifier sid) =>
            names.TryGetValue(sid.Value, out var known) ? known : names[sid.Value] = AccountName(sid);

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = new List<DirectoryAccessRule>();
        foreach (AuthorizationRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule is ActiveDirectoryAccessRule adRule && adRule.IdentityReference is SecurityIdentifier sid)
            {
                rules.Add(new DirectoryAccessRule(
                    Name(sid),
                    adRule.ActiveDirectoryRights,
                    adRule.AccessControlType,
                    adRule.ObjectType,
                    adRule.IsInherited,
                    sid.Value,
                    adRule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)));
            }
        }
        return new DirectoryAcl(owner?.Value, owner is null ? null : Name(owner), rules);
    }

    // Same display as GetAccessRules(NTAccount): the account name, or the SID when it doesn't resolve.
    private static string AccountName(SecurityIdentifier sid) =>
        AccountName(sid, s => s.Translate(typeof(NTAccount)).Value);

    internal static string AccountName(SecurityIdentifier sid, Func<SecurityIdentifier, string> translate)
    {
        try
        {
            return translate(sid);
        }
        // Translate throws IdentityNotMappedException for an unknown SID. An LSA lookup failure (a trust that's down,
        // say) is a Win32Exception on .NET 10 and a plain SystemException on older runtimes. One SID that won't
        // translate mustn't fail the whole ACL read, so each of these falls back to the SID string.
        catch (SystemException ex) when (ex is IdentityNotMappedException or Win32Exception or UnauthorizedAccessException
                                         || ex.GetType() == typeof(SystemException))
        {
            return sid.Value;
        }
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

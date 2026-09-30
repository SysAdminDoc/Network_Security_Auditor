using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace NetworkSecurityAuditor.Services;

/// <summary>Where a well-known group's SID comes from.</summary>
public enum WellKnownGroupScope
{
    /// <summary>S-1-5-32-RID, the same in every domain. These groups can't be a primary group.</summary>
    Builtin,

    /// <summary>The domain SID plus the RID.</summary>
    Domain,

    /// <summary>The forest root domain's SID plus the RID (Enterprise Admins, Schema Admins).</summary>
    ForestRoot
}

/// <summary>
/// A group AD creates in every domain. It's found by SID, never by name, because the name is localized
/// ("Domänen-Admins", "Administrateurs") and can be renamed. <see cref="EnglishName"/> only labels a group
/// the directory doesn't return.
/// </summary>
public sealed record WellKnownGroup(string EnglishName, WellKnownGroupScope Scope, int Rid)
{
    public static readonly WellKnownGroup DomainAdmins = new("Domain Admins", WellKnownGroupScope.Domain, Tier0Principals.DomainAdminsRid);
    public static readonly WellKnownGroup EnterpriseAdmins = new("Enterprise Admins", WellKnownGroupScope.ForestRoot, Tier0Principals.EnterpriseAdminsRid);
    public static readonly WellKnownGroup SchemaAdmins = new("Schema Admins", WellKnownGroupScope.ForestRoot, Tier0Principals.SchemaAdminsRid);
    public static readonly WellKnownGroup Administrators = new("Administrators", WellKnownGroupScope.Builtin, 544);
    public static readonly WellKnownGroup AccountOperators = new("Account Operators", WellKnownGroupScope.Builtin, 548);
    public static readonly WellKnownGroup ServerOperators = new("Server Operators", WellKnownGroupScope.Builtin, 549);
    public static readonly WellKnownGroup BackupOperators = new("Backup Operators", WellKnownGroupScope.Builtin, 551);
    public static readonly WellKnownGroup RemoteDesktopUsers = new("Remote Desktop Users", WellKnownGroupScope.Builtin, 555);
}

/// <summary>
/// The SIDs and naming contexts group lookups need. In a single-domain forest the forest root is the domain.
/// </summary>
public sealed record DomainIdentity(string DomainSid, string? DomainDn, string ForestRootSid, string? ForestRootDn)
{
    public bool IsForestRoot => string.Equals(DomainSid, ForestRootSid, StringComparison.OrdinalIgnoreCase);

    public string SidOf(WellKnownGroup group) => group.Scope switch
    {
        WellKnownGroupScope.Builtin => string.Create(CultureInfo.InvariantCulture, $"S-1-5-32-{group.Rid}"),
        WellKnownGroupScope.ForestRoot => Tier0Principals.Of(ForestRootSid, group.Rid),
        _ => Tier0Principals.Of(DomainSid, group.Rid)
    };

    /// <summary>The search base holding the group: null for the domain root, or the forest root's DN.</summary>
    public string? SearchBaseOf(WellKnownGroup group) =>
        group.Scope == WellKnownGroupScope.ForestRoot && !IsForestRoot ? ForestRootDn : null;

    /// <summary>The RID of an account or group in this domain, otherwise null.</summary>
    public int? Rid(string? sid) => Tier0Principals.Rid(sid, DomainSid);

    public bool IsTier0(string? sid) => Tier0Principals.IsTier0(sid, DomainSid, IsForestRoot ? null : ForestRootSid);
}

/// <summary>A well-known group as the directory returned it. <see cref="Name"/> is the directory's (localized) name.</summary>
public sealed record ResolvedGroup(
    WellKnownGroup Group,
    string Sid,
    string? SearchBase,
    string? DistinguishedName,
    string Name,
    IReadOnlyList<string> DirectMembers)
{
    public bool Found => DistinguishedName is not null;
}

/// <summary>
/// One member of a privileged group, direct or nested. <see cref="Chain"/> runs from the privileged group to
/// the member, so <see cref="Path"/> reads "Domain Admins > Tier0-Ops > alice".
/// </summary>
public sealed record GroupMember(
    string DistinguishedName,
    string Name,
    IReadOnlyList<string> Chain,
    bool IsGroup,
    DirectoryRecord? Record,
    string? ReadError = null)
{
    public string Path => string.Join(" > ", Chain);

    /// <summary>True when the membership comes through at least one nested group.</summary>
    public bool IsNested => Chain.Count > 2;

    /// <summary>True when the account is in the group only through its primaryGroupID.</summary>
    public bool ViaPrimaryGroup { get; init; }
}

/// <summary>
/// Finds privileged groups by domain SID plus RID and expands their membership, nested groups included.
/// </summary>
/// <remarks>
/// Membership comes from one LDAP_MATCHING_RULE_IN_CHAIN search per group, which returns every transitive
/// member in the group's naming context. Paths are rebuilt from each member's memberOf. Members whose
/// primaryGroupID is the group are added by the same search, since primary-group membership never shows in
/// member or memberOf. Direct members the search can't see (objects in another domain) are read one by one.
/// Known gaps: a group nested from another domain isn't expanded further, and an account whose primary group
/// is a group nested inside the privileged group isn't found.
/// </remarks>
public sealed class PrivilegedGroupResolver
{
    /// <summary>LDAP_MATCHING_RULE_IN_CHAIN: evaluates a linked attribute transitively.</summary>
    public const string InChainRule = "1.2.840.113556.1.4.1941";

    private static readonly string[] s_memberProperties =
        ["distinguishedName", "sAMAccountName", "objectClass", "memberOf", "primaryGroupID", "objectSid"];

    private readonly IDirectoryReader _reader;

    private PrivilegedGroupResolver(IDirectoryReader reader, DomainIdentity identity)
    {
        _reader = reader;
        Identity = identity;
    }

    public DomainIdentity Identity { get; }

    /// <summary>Reads the domain and forest root SIDs, then returns a resolver bound to them.</summary>
    public static PrivilegedGroupResolver Create(IDirectoryReader reader, CancellationToken ct) =>
        new(reader, ReadIdentity(reader, ct));

    /// <summary>
    /// The domain SID from the domain root, and the forest root's SID through RootDSE rootDomainNamingContext.
    /// When RootDSE or the forest root can't be read, the domain stands in for the forest root.
    /// </summary>
    public static DomainIdentity ReadIdentity(IDirectoryReader reader, CancellationToken ct)
    {
        var root = reader.ReadEntry(null, ["objectSid", "distinguishedName"], ct);
        var domainSid = root.Sid("objectSid")
            ?? throw new InvalidOperationException("The domain root returned no objectSid, so privileged groups can't be found by SID.");
        var domainDn = root.String("distinguishedName");

        try
        {
            var rootDn = reader.ReadEntry(DirectoryReader.RootDse, ["rootDomainNamingContext"], ct).String("rootDomainNamingContext");
            if (!string.IsNullOrEmpty(rootDn) && !string.Equals(rootDn, domainDn, StringComparison.OrdinalIgnoreCase) &&
                reader.ReadEntry(rootDn, ["objectSid"], ct).Sid("objectSid") is { } rootSid)
            {
                return new DomainIdentity(domainSid, domainDn, rootSid, rootDn);
            }
        }
        catch (COMException)
        {
            // RootDSE or the forest root isn't readable from here; treat the domain as its own forest root.
        }

        return new DomainIdentity(domainSid, domainDn, domainSid, domainDn);
    }

    /// <summary>Finds a well-known group by SID in the naming context that holds it.</summary>
    public ResolvedGroup Resolve(WellKnownGroup group, CancellationToken ct)
    {
        var sid = Identity.SidOf(group);
        var searchBase = Identity.SearchBaseOf(group);
        var query = new DirectoryQuery($"(objectSid={sid})", ["distinguishedName", "sAMAccountName", "member"])
        {
            SearchBase = searchBase,
            SizeLimit = 1
        };
        var record = _reader.Search(query, ct).FirstOrDefault();
        var dn = record?.String("distinguishedName");
        if (record is null || string.IsNullOrEmpty(dn))
            return new ResolvedGroup(group, sid, searchBase, null, group.EnglishName, []);

        var name = record.String("sAMAccountName") is { Length: > 0 } sam ? sam : CommonName(dn) ?? group.EnglishName;
        var members = record.Strings("member").Where(m => m.Length > 0).ToArray();
        return new ResolvedGroup(group, sid, searchBase, dn, name, members);
    }

    /// <summary>
    /// Every member of the group, nested ones included, each with its path. <paramref name="properties"/> are
    /// read on each member in addition to the ones the path needs.
    /// </summary>
    public IReadOnlyList<GroupMember> Members(ResolvedGroup group, IReadOnlyList<string> properties, CancellationToken ct)
    {
        if (!group.Found)
            return [];

        var groupDn = group.DistinguishedName!;
        var props = s_memberProperties.Concat(properties).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var inChain = $"(memberOf:{InChainRule}:={EscapeFilterValue(groupDn)})";
        var canBePrimary = group.Group.Scope != WellKnownGroupScope.Builtin;
        var filter = canBePrimary
            ? string.Create(CultureInfo.InvariantCulture, $"(|{inChain}(primaryGroupID={group.Group.Rid}))")
            : inChain;

        var found = new List<(string Dn, DirectoryRecord Record)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { groupDn };
        foreach (var record in _reader.Search(new DirectoryQuery(filter, props) { SearchBase = group.SearchBase }, ct))
        {
            ct.ThrowIfCancellationRequested();
            if (record.String("distinguishedName") is { Length: > 0 } dn && seen.Add(dn))
                found.Add((dn, record));
        }

        var chains = BuildChains(group, found);
        var members = new List<GroupMember>(found.Count + group.DirectMembers.Count);
        foreach (var (dn, record) in found)
        {
            var name = NameOf(record, dn);
            if (chains.TryGetValue(dn, out var chain))
            {
                members.Add(new GroupMember(dn, name, chain, IsGroup(record), record));
            }
            else if (canBePrimary && record.Int("primaryGroupID") == group.Group.Rid)
            {
                members.Add(new GroupMember(dn, name, [group.Name, name], IsGroup(record), record) { ViaPrimaryGroup = true });
            }
            else
            {
                // In the chain, but through a group whose own membership isn't visible here.
                members.Add(new GroupMember(dn, name, [group.Name, "...", name], IsGroup(record), record));
            }
        }

        // Direct members the in-chain search didn't return live outside its naming context.
        foreach (var dn in group.DirectMembers)
        {
            if (!seen.Add(dn))
                continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                var record = _reader.ReadEntry(dn, props, ct);
                var name = NameOf(record, dn);
                members.Add(new GroupMember(dn, name, [group.Name, name], IsGroup(record), record));
            }
            catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
            {
                members.Add(new GroupMember(dn, dn, [group.Name, dn], false, null, ex.Message));
            }
        }

        return members;
    }

    /// <summary>Escapes a value for an LDAP filter (RFC 4515), for example a DN holding parentheses.</summary>
    public static string EscapeFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length + 8);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    // Breadth-first from the privileged group over memberOf edges, so each member gets its shortest path.
    private static Dictionary<string, IReadOnlyList<string>> BuildChains(ResolvedGroup group, List<(string Dn, DirectoryRecord Record)> found)
    {
        var groupDn = group.DistinguishedName!;
        var nestedGroups = new HashSet<string>(found.Where(f => IsGroup(f.Record)).Select(f => f.Dn), StringComparer.OrdinalIgnoreCase);
        var children = new Dictionary<string, List<(string Dn, DirectoryRecord Record)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var member in found)
        {
            foreach (var parent in member.Record.Strings("memberOf"))
            {
                if (!string.Equals(parent, groupDn, StringComparison.OrdinalIgnoreCase) && !nestedGroups.Contains(parent))
                    continue;
                if (!children.TryGetValue(parent, out var list))
                    children[parent] = list = [];
                list.Add(member);
            }
        }

        var chains = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase) { [groupDn] = [group.Name] };
        var queue = new Queue<string>();
        queue.Enqueue(groupDn);
        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            if (!children.TryGetValue(parent, out var kids))
                continue;
            foreach (var (dn, record) in kids)
            {
                if (chains.ContainsKey(dn))
                    continue;
                chains[dn] = [.. chains[parent], NameOf(record, dn)];
                if (nestedGroups.Contains(dn))
                    queue.Enqueue(dn);
            }
        }

        chains.Remove(groupDn);
        return chains;
    }

    private static bool IsGroup(DirectoryRecord record) =>
        record.Strings("objectClass").Any(oc => string.Equals(oc, "group", StringComparison.OrdinalIgnoreCase));

    private static string NameOf(DirectoryRecord record, string dn) =>
        record.String("sAMAccountName") is { Length: > 0 } sam ? sam : dn;

    // "CN=Domänen-Admins,CN=Users,DC=corp,DC=example" gives "Domänen-Admins".
    private static string? CommonName(string dn)
    {
        if (!dn.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            return null;
        var sb = new StringBuilder();
        for (var i = 3; i < dn.Length; i++)
        {
            if (dn[i] == '\\' && i + 1 < dn.Length)
            {
                sb.Append(dn[++i]);
                continue;
            }
            if (dn[i] == ',')
                break;
            sb.Append(dn[i]);
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }
}

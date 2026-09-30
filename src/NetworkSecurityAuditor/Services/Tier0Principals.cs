using System.Collections.Frozen;
using System.Globalization;

namespace NetworkSecurityAuditor.Services;

/// <summary>
/// Tier 0 principals by SID, so checks give the same answer in a German or French domain as in an English one.
/// The set is AD's protected accounts and groups (the ones AdminSDHolder covers) plus SYSTEM and Enterprise
/// Domain Controllers. Domain groups are the domain SID plus a well-known RID; Enterprise Admins and Schema
/// Admins carry the forest root domain's SID.
/// </summary>
public static class Tier0Principals
{
    public const string LocalSystem = "S-1-5-18";
    public const string EnterpriseDomainControllers = "S-1-5-9";
    public const string BuiltinAdministrators = "S-1-5-32-544";
    public const string AccountOperators = "S-1-5-32-548";
    public const string ServerOperators = "S-1-5-32-549";
    public const string PrintOperators = "S-1-5-32-550";
    public const string BackupOperators = "S-1-5-32-551";
    public const string Replicator = "S-1-5-32-552";

    public const int AdministratorRid = 500;
    public const int KrbtgtRid = 502;
    public const int DomainAdminsRid = 512;
    public const int DomainControllersRid = 516;
    public const int SchemaAdminsRid = 518;
    public const int EnterpriseAdminsRid = 519;
    public const int ReadOnlyDomainControllersRid = 521;
    public const int KeyAdminsRid = 526;
    public const int EnterpriseKeyAdminsRid = 527;

    private static readonly FrozenSet<string> s_fixed = FrozenSet.ToFrozenSet(
        [LocalSystem, EnterpriseDomainControllers, BuiltinAdministrators, AccountOperators, ServerOperators,
         PrintOperators, BackupOperators, Replicator],
        StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<int> s_domainRids = FrozenSet.ToFrozenSet(
        [AdministratorRid, KrbtgtRid, DomainAdminsRid, DomainControllersRid, ReadOnlyDomainControllersRid,
         KeyAdminsRid, EnterpriseKeyAdminsRid]);

    private static readonly FrozenSet<int> s_forestRootRids = FrozenSet.ToFrozenSet(
        [SchemaAdminsRid, EnterpriseAdminsRid, EnterpriseKeyAdminsRid]);

    /// <summary>The SID of a domain-relative principal, for example Domain Admins is <c>Of(domainSid, 512)</c>.</summary>
    public static string Of(string domainSid, int rid) => string.Create(CultureInfo.InvariantCulture, $"{domainSid}-{rid}");

    /// <summary>The RID when <paramref name="sid"/> belongs to <paramref name="domainSid"/>, otherwise null.</summary>
    public static int? Rid(string? sid, string? domainSid)
    {
        if (sid is null || domainSid is null || sid.Length <= domainSid.Length + 1 ||
            !sid.StartsWith(domainSid, StringComparison.OrdinalIgnoreCase) || sid[domainSid.Length] != '-')
        {
            return null;
        }
        return int.TryParse(sid.AsSpan(domainSid.Length + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var rid) ? rid : null;
    }

    /// <summary>
    /// True for a Tier 0 principal of this domain, of the forest root (Enterprise and Schema Admins), or a
    /// builtin one. Pass the forest root SID when it differs from the domain's; null means a single-domain forest.
    /// </summary>
    public static bool IsTier0(string? sid, string domainSid, string? forestRootSid = null)
    {
        if (sid is null) return false;
        if (s_fixed.Contains(sid)) return true;
        if (Rid(sid, domainSid) is { } rid && (s_domainRids.Contains(rid) || s_forestRootRids.Contains(rid))) return true;
        return Rid(sid, forestRootSid ?? domainSid) is { } rootRid && s_forestRootRids.Contains(rootRid);
    }

    /// <summary>Reads the domain SID from the domain root's objectSid.</summary>
    public static string? ReadDomainSid(IDirectoryReader reader, CancellationToken ct) =>
        reader.ReadEntry(null, ["objectSid"], ct).Sid("objectSid");
}

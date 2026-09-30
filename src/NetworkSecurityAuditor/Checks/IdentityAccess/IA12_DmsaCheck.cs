namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA12 - BadSuccessor / dMSA exposure (Akamai, "BadSuccessor: Abusing dMSA to Escalate Privileges in Active
/// Directory", May 2025; fixed as CVE-2025-53779 in the August 12, 2025 update).
/// A delegated Managed Service Account (dMSA) takes on the privileges of the account named in its
/// msDS-ManagedAccountPrecededByLink once msDS-DelegatedMSAState says the migration is complete. Whoever can create
/// a dMSA in an OU or container, or write those two attributes on an existing one, can point it at a Domain Admin.
/// One Windows Server 2025 DC is enough, whatever the functional level. The August 2025 update (KB5063878, OS build
/// 26100.4946, or hotpatch KB5064010, 26100.4851) makes the KDC require the target to link back, so a one-way link
/// stops working, but the same rights still reach the keys of any account their holder can already write.
/// Principals are matched by SID through <see cref="Tier0Principals"/>, so a localized domain gives the same answer.
/// </summary>
public sealed class IA12_DmsaCheck : ISecurityCheck
{
    public string Id => "IA12";

    // schemaIDGUIDs from the Windows Server 2025 schema update (Sch89.ldf), [MS-ADSC] and [MS-ADA2].
    internal static readonly Guid DmsaClass = new("0feb936f-47b3-49f2-9386-1dedc2c23765");
    internal static readonly Guid PrecededByLinkAttribute = new("a0945b2b-57a2-43bd-b327-4d112a4e8bd1");
    internal static readonly Guid DelegatedMsaStateAttribute = new("2f5c138a-bd38-4016-88b4-0ec87cbb4919");

    internal const string CreatorOwner = "S-1-3-0";
    internal const string CreatorGroup = "S-1-3-1";
    internal const string OwnerRights = "S-1-3-4";
    internal const string PrincipalSelf = "S-1-5-10";

    /// <summary>KB5063878 (August 12, 2025) brings Windows Server 2025 to OS build 26100.4946.</summary>
    internal const int FixedUbr = 4946;
    /// <summary>The August 2025 hotpatch, KB5064010, is OS build 26100.4851; later hotpatches are above 4946.</summary>
    internal const int FixedHotpatchUbr = 4851;
    internal const int Server2025Build = 26100;
    internal const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    internal const int MaxAclObjects = 1000;
    internal const int MaxDmsaAcls = 200;
    internal const int MaxDcPatchReads = 25;

    /// <summary>
    /// How long all the DC patch reads may take together. Each read has its own timeout, but one after another they
    /// could outlast the runner's 90-second check timeout and lose every finding, so DCs past this are reported as
    /// not read.
    /// </summary>
    internal static readonly TimeSpan DcReadBudget = TimeSpan.FromSeconds(45);
    private const int MaxEvidenceGrants = 30;

    internal const string DcFilter =
        "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))";
    internal const string DmsaFilter = "(objectClass=msDS-DelegatedManagedServiceAccount)";
    internal const string OuFilter = "(objectCategory=organizationalUnit)";
    internal const string ContainerFilter = "(objectCategory=container)";

    internal enum AclScope { Container, Dmsa }

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;
    private readonly IRemoteRegistryReader _registry;

    /// <summary>Times the DC patch reads against <see cref="DcReadBudget"/>. Tests swap in a clock they advance.</summary>
    internal TimeProvider Clock { get; init; } = TimeProvider.System;

    public IA12_DmsaCheck() : this(env => new LdapDirectoryReader(env.DomainName), new RemoteRegistryReader()) { }

    internal IA12_DmsaCheck(Func<EnvironmentInfo, IDirectoryReader> directory, IRemoteRegistryReader registry)
    {
        _directory = directory;
        _registry = registry;
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. dMSA/BadSuccessor check requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            return Task.FromResult(Run(_directory(env), ct));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private CheckResult Run(IDirectoryReader directory, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        int critical = 0, review = 0;

        // Domain root first: an unreachable domain is an error, not a pass.
        var domain = directory.ReadEntry(null, ["distinguishedName", "objectSid"], ct);
        string domainDn = domain.String("distinguishedName") ?? "";
        string? domainSid = domain.Sid("objectSid");

        evidence.AppendLine("[Domain]");
        evidence.AppendLine($"  Domain DN: {domainDn}");
        evidence.AppendLine($"  Domain SID: {domainSid ?? "unreadable"}");
        string? forestRootSid = ReadForestRootSid(directory, domainDn, evidence, ct);
        if (domainSid is null)
        {
            review++;
            sb.AppendLine("REVIEW: The domain SID couldn't be read, so only builtin principals count as Tier 0 and domain groups may be listed below.");
        }
        bool IsTier0(string? sid) => Tier0Principals.IsTier0(sid, domainSid ?? "", forestRootSid);

        // 1. Windows Server 2025 DCs gate the attack; the functional level doesn't.
        ct.ThrowIfCancellationRequested();
        var dcs = ReadServer2025Dcs(directory, sb, evidence, ref critical, ref review, ct);
        bool exposed = dcs.ListFailed || dcs.Server2025 > 0;
        bool allPatched = !dcs.ListFailed && dcs.Server2025 > 0 && dcs.Unpatched == 0 && dcs.Unknown == 0;

        // 2. dMSA inventory. Existence alone is informational; a link to a Tier 0 account isn't.
        ct.ThrowIfCancellationRequested();
        var dmsas = ReadDmsas(directory, sb, evidence, IsTier0, ref critical, ref review, ct);

        // 3. Who can create a dMSA in any OU or container, or rewrite an existing dMSA's link.
        ct.ThrowIfCancellationRequested();
        string msaCn = $"CN=Managed Service Accounts,{domainDn}";
        bool msaExists = false;
        evidence.AppendLine("\n[Managed Service Accounts Container]");
        try
        {
            // Binding the container proves it exists; its ACL is read with the sweep.
            directory.ReadEntry(msaCn, ["distinguishedName"], ct);
            evidence.AppendLine($"  Container DN: {msaCn}");
            evidence.AppendLine("  Container exists and is accessible.");
            msaExists = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine("  Managed Service Accounts container not found or inaccessible.");
        }

        List<string> risky = [];
        if (exposed)
        {
            risky = SweepAcls(directory, domainDn, msaExists ? msaCn : null, dmsas, IsTier0, sb, evidence, ref review, ct);
        }
        else
        {
            evidence.AppendLine("\n[dMSA create and control rights]");
            evidence.AppendLine("  Skipped: no Windows Server 2025 DC, so no KDC can honor a dMSA link.");
        }

        if (risky.Count > 0)
        {
            if (allPatched)
            {
                review++;
                sb.AppendLine($"WARNING: {risky.Count} non-Tier-0 principal(s) can create or take over dMSA objects. Every Windows Server 2025 DC has the August 2025 fix, so a one-way link no longer works, but these rights still let the holder pull the keys of any account it can already write. Remove them unless the delegation is intended:");
            }
            else
            {
                critical++;
                sb.AppendLine($"CRITICAL: {risky.Count} non-Tier-0 principal(s) can create or take over dMSA objects while a Windows Server 2025 DC isn't confirmed patched. Any of them can link a dMSA to a Domain Admin and take its privileges:");
            }
            foreach (var line in risky)
                sb.AppendLine(line);
        }

        if (!exposed)
        {
            sb.AppendLine("INFO: No domain controller runs Windows Server 2025, so no KDC can issue dMSA tickets and BadSuccessor doesn't apply here. Rerun this check after adding a 2025 DC.");
        }

        sb.AppendLine("Reference: CVE-2025-53779 (BadSuccessor), fixed by KB5063878 (OS build 26100.4946) on August 12, 2025.");
        if (critical == 0 && review == 0)
        {
            sb.AppendLine(dmsas.Count == 0
                ? "PASS: No dMSA objects or suspicious delegations detected."
                : "PASS: No suspicious dMSA links or delegations detected.");
        }

        return new CheckResult
        {
            Status = critical > 0 ? CheckStatus.Fail : review > 0 ? CheckStatus.Partial : CheckStatus.Pass,
            Findings = sb.ToString().TrimEnd(),
            Evidence = evidence.ToString().TrimEnd()
        };
    }

    private static string? ReadForestRootSid(IDirectoryReader directory, string domainDn, StringBuilder evidence, CancellationToken ct)
    {
        try
        {
            // RootDSE on the machine domain's server, the domain every other read here assesses. A serverless bind
            // follows the signed-in user's domain, which for an auditor from a trusted forest names the wrong forest root.
            var rootDse = directory.ReadEntry(DirectoryReader.RootDse,
                ["domainFunctionality", "forestFunctionality", "rootDomainNamingContext"], ct);
            // Informational: the functional level doesn't gate BadSuccessor, one 2025 DC does.
            evidence.AppendLine($"  Domain Functional Level: {rootDse.String("domainFunctionality")}");
            evidence.AppendLine($"  Forest Functional Level: {rootDse.String("forestFunctionality")}");

            string? rootDn = rootDse.String("rootDomainNamingContext");
            if (string.IsNullOrEmpty(rootDn) || string.Equals(rootDn, domainDn, StringComparison.OrdinalIgnoreCase))
                return null;
            string? sid = directory.ReadEntry(rootDn, ["objectSid"], ct).Sid("objectSid");
            evidence.AppendLine($"  Forest root SID: {sid ?? "unreadable"}");
            return sid;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  Could not read RootDSE or the forest root: {ex.Message}");
            return null;
        }
    }

    private sealed record DcSummary(int Total, int Server2025, int Unpatched, int Unknown, bool ListFailed);

    private DcSummary ReadServer2025Dcs(IDirectoryReader directory, StringBuilder sb, StringBuilder evidence,
        ref int critical, ref int review, CancellationToken ct)
    {
        evidence.AppendLine("\n[Domain Controllers]");
        IReadOnlyList<DirectoryRecord> dcs;
        try
        {
            dcs = directory.Search(new DirectoryQuery(DcFilter,
                ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion"]), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            review++;
            evidence.AppendLine($"  Could not list domain controllers: {ex.Message}");
            sb.AppendLine($"REVIEW: Couldn't list domain controllers ({ex.Message}), so the check assumes a Windows Server 2025 DC may exist.");
            return new DcSummary(0, 0, 0, 0, ListFailed: true);
        }

        int server2025 = 0, unpatched = 0, unknown = 0, reads = 0, notRead = 0;
        long started = Clock.GetTimestamp();
        foreach (var dc in dcs.OrderBy(d => d.String("dNSHostName") ?? d.String("name"), StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            string name = dc.String("name") ?? "";
            string host = dc.String("dNSHostName") ?? name;
            string? os = dc.String("operatingSystem");
            string? version = dc.String("operatingSystemVersion");
            if (!IsServer2025(os, version))
            {
                evidence.AppendLine($"  {host} | {os} | {version} | Server 2025: no");
                continue;
            }

            server2025++;
            string? skipped = reads >= MaxDcPatchReads ? $"limit of {MaxDcPatchReads} DCs"
                : Clock.GetElapsedTime(started) >= DcReadBudget ? $"the {DcReadBudget.TotalSeconds:0}-second budget for DC reads ran out"
                : null;
            if (skipped is not null)
            {
                unknown++;
                notRead++;
                evidence.AppendLine($"  {host} | {os} | {version} | Server 2025: yes | patch level not read ({skipped})");
                continue;
            }
            reads++;

            var (ubr, error) = ReadUbr(host, ct);
            switch (PatchStateOf(ubr))
            {
                case PatchState.Patched:
                    evidence.AppendLine($"  {host} | {os} | {version} | Server 2025: yes | build {Server2025Build}.{ubr} (remote registry UBR) | August 2025 fix: installed");
                    break;
                case PatchState.Unpatched:
                    unpatched++;
                    critical++;
                    evidence.AppendLine($"  {host} | {os} | {version} | Server 2025: yes | build {Server2025Build}.{ubr} (remote registry UBR) | August 2025 fix: missing");
                    sb.AppendLine($"CRITICAL: {host} runs Windows Server 2025 build {Server2025Build}.{ubr}, below the August 2025 update (KB5063878, build {Server2025Build}.{FixedUbr}) that fixes CVE-2025-53779. Install the latest cumulative update.");
                    break;
                default:
                    unknown++;
                    review++;
                    evidence.AppendLine($"  {host} | {os} | {version} | Server 2025: yes | patch level unreadable: {error}");
                    sb.AppendLine($"REVIEW: {host} runs Windows Server 2025 but its patch level couldn't be read over remote registry ({error}). Confirm it has KB5063878 (build {Server2025Build}.{FixedUbr}) or a later update.");
                    break;
            }
        }

        if (notRead > 0)
        {
            review++;
            sb.AppendLine($"REVIEW: The patch level of {notRead} Windows Server 2025 DC(s) wasn't read, so they aren't counted as patched. Confirm each has KB5063878 (build {Server2025Build}.{FixedUbr}) or a later update.");
        }
        sb.Insert(0, $"Windows Server 2025 domain controllers: {server2025} of {dcs.Count}{Environment.NewLine}");
        return new DcSummary(dcs.Count, server2025, unpatched, unknown, ListFailed: false);
    }

    private (int? Ubr, string Error) ReadUbr(string host, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host))
            return (null, "no host name");
        try
        {
            object? value = _registry.ReadMachineValue(host, CurrentVersionKey, "UBR", ct);
            return value switch
            {
                int i => (i, ""),
                long l when l is >= 0 and <= int.MaxValue => ((int)l, ""),
                string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => (parsed, ""),
                null => (null, "UBR value missing"),
                _ => (null, $"unexpected UBR value {value}")
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, ex.Message);
        }
    }

    internal enum PatchState { Unknown, Unpatched, Patched }

    /// <summary>Whether a Windows Server 2025 update build revision (UBR) includes the August 2025 fix.</summary>
    internal static PatchState PatchStateOf(int? ubr) => ubr switch
    {
        null => PatchState.Unknown,
        >= FixedUbr or FixedHotpatchUbr => PatchState.Patched,
        _ => PatchState.Unpatched
    };

    /// <summary>True for a DC reporting Windows Server 2025 in operatingSystem, or build 26100 in operatingSystemVersion.</summary>
    internal static bool IsServer2025(string? operatingSystem, string? operatingSystemVersion)
    {
        if (operatingSystem is not null &&
            operatingSystem.Contains("Server", StringComparison.OrdinalIgnoreCase) &&
            operatingSystem.Contains("2025", StringComparison.Ordinal))
        {
            return true;
        }
        var build = operatingSystemVersion is null ? null : Regex.Match(operatingSystemVersion, @"\((\d+)\)");
        return build is { Success: true } &&
            int.TryParse(build.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) &&
            number == Server2025Build;
    }

    private sealed record Dmsa(string Sam, string Dn);

    private static List<Dmsa> ReadDmsas(IDirectoryReader directory, StringBuilder sb, StringBuilder evidence,
        Func<string?, bool> isTier0, ref int critical, ref int review, CancellationToken ct)
    {
        evidence.AppendLine("\n[Delegated Managed Service Accounts (dMSA)]");
        var found = new List<Dmsa>();
        try
        {
            var query = new DirectoryQuery(DmsaFilter,
                ["sAMAccountName", "distinguishedName", "msDS-ManagedAccountPrecededByLink", "msDS-DelegatedMSAState", "whenCreated"]);
            foreach (var sr in directory.Search(query, ct))
            {
                ct.ThrowIfCancellationRequested();
                string sam = sr.String("sAMAccountName") ?? "";
                string dn = sr.String("distinguishedName") ?? "";
                found.Add(new Dmsa(sam, dn));

                string? link = sr.String("msDS-ManagedAccountPrecededByLink");
                int state = sr.Int("msDS-DelegatedMSAState", -1);
                DateTime created = sr.Time("whenCreated") ?? DateTime.MinValue;

                evidence.AppendLine($"  {sam} | DN={dn}");
                evidence.AppendLine($"    Linked account (msDS-ManagedAccountPrecededByLink): {link ?? "none"}");
                evidence.AppendLine($"    State (msDS-DelegatedMSAState): {StateName(state)}");
                evidence.AppendLine($"    Created: {created:yyyy-MM-dd}");

                if (link is not null)
                    CheckLink(directory, sam, dn, link, isTier0, sb, evidence, ref critical, ref review, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  dMSA query error (object class may not exist in schema): {ex.Message}");
        }

        sb.AppendLine($"Delegated Managed Service Accounts found: {found.Count}");
        if (found.Count > 0)
            sb.AppendLine($"INFO: {found.Count} dMSA object(s) exist. That's normal on its own; links and rights are checked below.");
        return found;
    }

    private static string StateName(int state) => state switch
    {
        -1 => "not set",
        1 => "1 (migration started)",
        2 => "2 (migration completed)",
        _ => state.ToString(CultureInfo.InvariantCulture)
    };

    private static void CheckLink(IDirectoryReader directory, string sam, string dmsaDn, string link,
        Func<string?, bool> isTier0, StringBuilder sb, StringBuilder evidence, ref int critical, ref int review, CancellationToken ct)
    {
        DirectoryRecord target;
        try
        {
            target = directory.ReadEntry(link,
                ["objectSid", "sAMAccountName", "adminCount", "tokenGroups", "msDS-SupersededManagedAccountLink"], ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            review++;
            evidence.AppendLine($"    Could not read the linked account: {ex.Message}");
            sb.AppendLine($"REVIEW: dMSA {sam} is linked to {link}, which couldn't be read ({ex.Message}). Confirm the account isn't privileged.");
            return;
        }

        string name = target.String("sAMAccountName") ?? link;
        bool mutual = target.Strings("msDS-SupersededManagedAccountLink")
            .Any(value => string.Equals(value, dmsaDn, StringComparison.OrdinalIgnoreCase));
        string? privilege = PrivilegeOf(target, isTier0);
        evidence.AppendLine($"    Linked account: {name} | SID={target.Sid("objectSid") ?? "unknown"} | links back (msDS-SupersededManagedAccountLink): {(mutual ? "yes" : "no")} | {privilege ?? "not Tier 0"}");

        if (privilege is null)
            return;

        critical++;
        sb.AppendLine(mutual
            ? $"CRITICAL: dMSA {sam} is linked to {name} ({privilege}), and that account links back, so even patched DCs give the dMSA its privileges. Unless this is a documented migration of that account, remove the link and investigate."
            : $"CRITICAL: dMSA {sam} is linked to {name} ({privilege}) with a one-way link. The August 2025 update rejects one-way links, but an unpatched Windows Server 2025 DC honors it, and it's the BadSuccessor pattern. Remove the link and investigate who set it.");
    }

    /// <summary>Why a linked account is privileged, by SID and token groups, or null when it isn't.</summary>
    internal static string? PrivilegeOf(DirectoryRecord account, Func<string?, bool> isTier0)
    {
        string? sid = account.Sid("objectSid");
        if (isTier0(sid))
            return $"Tier 0 account {sid}";
        foreach (var group in account.Values("tokenGroups").OfType<byte[]>())
        {
            string groupSid = new SecurityIdentifier(group, 0).Value;
            if (isTier0(groupSid))
                return $"member of Tier 0 group {groupSid}";
        }
        return account.Int("adminCount") == 1 ? "protected account, adminCount=1" : null;
    }

    private sealed class Principal(string identity, string? sid)
    {
        public string Identity { get; } = identity;
        public string? Sid { get; } = sid;
        public List<(string Dn, string Reason)> Grants { get; } = [];
    }

    private static List<string> SweepAcls(IDirectoryReader directory, string domainDn, string? msaCn, List<Dmsa> dmsas,
        Func<string?, bool> isTier0, StringBuilder sb, StringBuilder evidence, ref int review, CancellationToken ct)
    {
        evidence.AppendLine("\n[dMSA create and control rights]");

        // Where a dMSA can be created (possible superiors: container, organizationalUnit, plus the domain root),
        // most likely places first so the cap cuts the long tail: existing dMSAs' parents, the default container.
        var targets = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? dn)
        {
            if (!string.IsNullOrEmpty(dn) && seen.Add(dn))
                targets.Add(dn);
        }
        Add(domainDn);
        foreach (var dmsa in dmsas)
            Add(ParentDn(dmsa.Dn));
        Add(msaCn);
        foreach (var filter in new[] { OuFilter, ContainerFilter })
        {
            try
            {
                foreach (var record in directory.Search(new DirectoryQuery(filter, ["distinguishedName"]), ct))
                    Add(record.String("distinguishedName"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                review++;
                evidence.AppendLine($"  Search {filter} failed: {ex.Message}");
                sb.AppendLine($"REVIEW: Couldn't list {(filter == OuFilter ? "OUs" : "containers")} ({ex.Message}); their ACLs weren't inspected.");
            }
        }

        var principals = new Dictionary<string, Principal>(StringComparer.OrdinalIgnoreCase);
        void Record(string? sid, string identity, string dn, string reason)
        {
            string key = sid ?? identity;
            if (!principals.TryGetValue(key, out var principal))
                principals[key] = principal = new Principal(identity, sid);
            principal.Grants.Add((dn, reason));
        }

        int unreadable = 0;
        int inspected = 0;
        foreach (var dn in targets.Take(MaxAclObjects))
        {
            ct.ThrowIfCancellationRequested();
            inspected++;
            DirectoryAcl acl;
            try
            {
                acl = directory.ReadAcl(dn, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                unreadable++;
                evidence.AppendLine($"  Could not read ACL of {dn}: {ex.Message}");
                if (string.Equals(dn, msaCn, StringComparison.OrdinalIgnoreCase))
                {
                    evidence.AppendLine($"  Could not read ACLs: {ex.Message}");
                    sb.AppendLine("INFO: Could not read MSA container ACLs (access denied or insufficient privileges).");
                }
                continue;
            }

            if (string.Equals(dn, msaCn, StringComparison.OrdinalIgnoreCase))
                DescribeMsaContainer(acl, evidence);
            foreach (var (sid, identity, reason) in RiskyGrants(acl, AclScope.Container, isTier0))
                Record(sid, identity, dn, reason);
        }

        int dmsaInspected = 0;
        foreach (var dmsa in dmsas.Take(MaxDmsaAcls))
        {
            ct.ThrowIfCancellationRequested();
            dmsaInspected++;
            try
            {
                foreach (var (sid, identity, reason) in RiskyGrants(directory.ReadAcl(dmsa.Dn, ct), AclScope.Dmsa, isTier0))
                    Record(sid, identity, dmsa.Dn, reason);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                unreadable++;
                evidence.AppendLine($"  Could not read ACL of {dmsa.Dn}: {ex.Message}");
            }
        }

        evidence.AppendLine($"  OUs, containers and domain root inspected: {inspected} of {targets.Count}");
        evidence.AppendLine($"  dMSA objects inspected: {dmsaInspected} of {dmsas.Count}");
        if (targets.Count > MaxAclObjects || dmsas.Count > MaxDmsaAcls)
        {
            review++;
            sb.AppendLine($"REVIEW: The ACL sweep stopped at its limit ({inspected} of {targets.Count} OUs and containers, {dmsaInspected} of {dmsas.Count} dMSAs). Review the rest with a targeted scan.");
        }
        if (unreadable > 0)
        {
            review++;
            sb.AppendLine($"REVIEW: {unreadable} ACL(s) couldn't be read, so rights on those objects weren't checked. See the evidence for which ones.");
        }

        var lines = new List<string>(principals.Count);
        foreach (var principal in principals.Values.OrderBy(p => p.Identity, StringComparer.OrdinalIgnoreCase))
        {
            var first = principal.Grants[0];
            string more = principal.Grants.Count > 1 ? $" (+{principal.Grants.Count - 1} more)" : "";
            lines.Add($"  {principal.Identity} ({principal.Sid ?? "SID unknown"}): {first.Reason} on {first.Dn}{more}");
            foreach (var (dn, reason) in principal.Grants.Take(MaxEvidenceGrants))
                evidence.AppendLine($"  [RISK] {principal.Identity} | {principal.Sid ?? "SID unknown"} | {reason} | {dn}");
            if (principal.Grants.Count > MaxEvidenceGrants)
                evidence.AppendLine($"  [RISK] {principal.Identity} | {principal.Grants.Count - MaxEvidenceGrants} more object(s) not listed");
        }
        if (principals.Count == 0)
            evidence.AppendLine("  No non-Tier-0 principal can create or take over dMSA objects on the inspected objects.");
        return lines;
    }

    // Kept from the original container report: every CreateChild ACE, allowed or denied.
    private static void DescribeMsaContainer(DirectoryAcl acl, StringBuilder evidence)
    {
        int createChild = 0;
        foreach (var rule in acl.Rules.Where(r => r.Rights.HasFlag(ActiveDirectoryRights.CreateChild)))
        {
            createChild++;
            evidence.AppendLine($"  CreateChild ACE: {rule.Identity} | Type={rule.Type}");
        }
        evidence.AppendLine($"  Total CreateChild ACEs: {createChild}");
    }

    /// <summary>
    /// The non-Tier-0 principals one ACL lets create a dMSA (container scope) or rewrite a dMSA's link (dMSA scope),
    /// with the reason. CREATOR OWNER and CREATOR GROUP are templates for new children, so what they grant shows up
    /// as the creator's own SID on the child. SELF on an OU or container names no one; on a dMSA it's the dMSA
    /// itself, which anyone allowed to use the dMSA can act as. The owner can always rewrite the DACL unless an
    /// OWNER RIGHTS entry narrows it. Deny entries aren't subtracted.
    /// </summary>
    internal static IEnumerable<(string? Sid, string Identity, string Reason)> RiskyGrants(
        DirectoryAcl acl, AclScope scope, Func<string?, bool> isTier0)
    {
        foreach (var rule in acl.Rules)
        {
            if (!IsReportable(rule.Sid, scope, isTier0))
                continue;
            if (RelevantRights(rule, scope) is { } reason)
                yield return (rule.Sid, rule.Identity, reason);
        }

        if (acl.OwnerSid is { } owner && IsReportable(owner, AclScope.Container, isTier0) &&
            OwnerReason(acl, scope) is { } ownerReason)
        {
            yield return (owner, acl.Owner ?? owner, ownerReason);
        }
    }

    internal static bool IsReportable(string? sid, AclScope scope, Func<string?, bool> isTier0) => sid switch
    {
        CreatorOwner or CreatorGroup or OwnerRights => false,
        PrincipalSelf => scope == AclScope.Dmsa,
        _ => !isTier0(sid)
    };

    /// <summary>The BadSuccessor-relevant rights one rule grants on the object it's on, or null for none.</summary>
    internal static string? RelevantRights(DirectoryAccessRule rule, AclScope scope)
    {
        if (rule.Type != AccessControlType.Allow || rule.InheritOnly)
            return null;

        var rights = rule.Rights;
        bool anyType = rule.ObjectType == Guid.Empty;
        if (anyType && rights.HasFlag(ActiveDirectoryRights.GenericAll))
            return "GenericAll";

        var parts = new List<string>(3);
        if (scope == AclScope.Container)
        {
            if ((rights & ActiveDirectoryRights.CreateChild) != 0 && (anyType || rule.ObjectType == DmsaClass))
                parts.Add(anyType ? "CreateChild (all classes)" : "CreateChild (msDS-DelegatedManagedServiceAccount)");
        }
        else if ((rights & ActiveDirectoryRights.WriteProperty) != 0)
        {
            if (anyType)
                parts.Add(rights.HasFlag(ActiveDirectoryRights.GenericWrite) ? "GenericWrite" : "WriteProperty (all attributes)");
            else if (rule.ObjectType == PrecededByLinkAttribute)
                parts.Add("WriteProperty (msDS-ManagedAccountPrecededByLink)");
            else if (rule.ObjectType == DelegatedMsaStateAttribute)
                parts.Add("WriteProperty (msDS-DelegatedMSAState)");
        }
        if (anyType && (rights & ActiveDirectoryRights.WriteDacl) != 0)
            parts.Add("WriteDacl");
        if (anyType && (rights & ActiveDirectoryRights.WriteOwner) != 0)
            parts.Add("WriteOwner");
        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    /// <summary>
    /// What the owner can do. An owner has implicit READ_CONTROL and WRITE_DAC, so it can grant itself anything,
    /// unless the DACL has an OWNER RIGHTS entry, which replaces those implicit rights with its own.
    /// </summary>
    internal static string? OwnerReason(DirectoryAcl acl, AclScope scope)
    {
        var ownerRules = acl.Rules.Where(r => r.Sid == OwnerRights && !r.InheritOnly).ToList();
        if (ownerRules.Count == 0)
            return "owner (implicit WriteDacl)";
        var granted = ownerRules.Select(r => RelevantRights(r, scope)).OfType<string>().ToList();
        return granted.Count == 0 ? null : "owner via OWNER RIGHTS: " + string.Join(", ", granted);
    }

    /// <summary>The parent of a DN, honoring escaped commas in the first RDN.</summary>
    internal static string? ParentDn(string dn)
    {
        for (int i = 0; i < dn.Length; i++)
        {
            if (dn[i] == '\\')
            {
                i++;
                continue;
            }
            if (dn[i] == ',')
                return dn[(i + 1)..];
        }
        return null;
    }
}

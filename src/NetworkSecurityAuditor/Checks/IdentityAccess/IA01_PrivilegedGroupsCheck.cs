namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA01 - Privileged Groups Review: Domain Admins, Enterprise Admins, Schema Admins,
/// Administrators, found by SID and expanded through nested groups. Flags stale members,
/// nested groups, PasswordNeverExpires.
/// </summary>
public sealed class IA01_PrivilegedGroupsCheck : ISecurityCheck
{
    public string Id => "IA01";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA01_PrivilegedGroupsCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA01_PrivilegedGroupsCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    private static readonly WellKnownGroup[] PrivilegedGroups =
    [
        WellKnownGroup.DomainAdmins,
        WellKnownGroup.EnterpriseAdmins,
        WellKnownGroup.SchemaAdmins,
        WellKnownGroup.Administrators
    ];

    private static readonly string[] MemberProperties = ["lastLogonTimestamp", "userAccountControl", "pwdLastSet"];

    // Findings list at most this many nested members per group; the evidence lists them all.
    private const int NestedFindingLimit = 10;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Privileged group review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            int totalPrivileged = 0;
            var staleThreshold = DateTime.UtcNow.AddDays(-90);
            var allPrivMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var directory = _directory(env);
            var resolver = PrivilegedGroupResolver.Create(directory, ct);

            foreach (var wellKnown in PrivilegedGroups)
            {
                ct.ThrowIfCancellationRequested();
                var group = resolver.Resolve(wellKnown, ct);
                evidence.AppendLine($"[{group.Name}]");

                if (!group.Found)
                {
                    evidence.AppendLine($"  Group not found. Looked up by SID {group.Sid}.");
                    continue;
                }

                var members = resolver.Members(group, MemberProperties, ct);
                int memberCount = members.Count;
                totalPrivileged += memberCount;
                sb.AppendLine($"{group.Name}: {memberCount} member(s).");
                evidence.AppendLine($"  Member count: {memberCount}");

                if (memberCount == 0) continue;

                int staleCount = 0;
                int neverExpireCount = 0;
                int nestedGroupCount = 0;
                var nestedAccounts = new List<GroupMember>();

                foreach (var member in members)
                {
                    ct.ThrowIfCancellationRequested();
                    // A member already reported under an earlier group (Domain Admins inside Administrators)
                    // isn't hidden privilege, so only first sightings go in the findings.
                    bool firstSighting = allPrivMembers.Add(member.DistinguishedName);
                    string via = member.IsNested ? $" | Path={member.Path}" : member.ViaPrimaryGroup ? " | PrimaryGroup" : "";

                    if (member.Record is not { } memberEntry)
                    {
                        evidence.AppendLine($"  {member.DistinguishedName} (could not read details)");
                        continue;
                    }

                    if (member.IsGroup)
                    {
                        nestedGroupCount++;
                        evidence.AppendLine($"  [NESTED GROUP] {member.Name}{via}");
                        continue;
                    }

                    if (member.IsNested && firstSighting) nestedAccounts.Add(member);

                    var lastLogon = memberEntry.FileTimeUtc("lastLogonTimestamp");
                    bool isStale = !lastLogon.HasValue || lastLogon.Value < staleThreshold;
                    if (isStale) staleCount++;

                    // Check PasswordNeverExpires (bit 0x10000 of userAccountControl)
                    int uac = memberEntry.Int("userAccountControl");
                    bool pwdNeverExpires = (uac & 0x10000) != 0;
                    if (pwdNeverExpires) neverExpireCount++;

                    string flags = "";
                    if (isStale) flags += " [STALE]";
                    if (pwdNeverExpires) flags += " [PwdNeverExpires]";

                    var lastLogonLabel = lastLogon.HasValue ? lastLogon.Value.ToString("yyyy-MM-dd") : "Never";
                    evidence.AppendLine($"  {member.Name} | LastLogon={lastLogonLabel}{flags}{via}");
                }

                if (staleCount > 0)
                {
                    hasIssue = true;
                    sb.AppendLine($"  WARNING: {staleCount} member(s) have not logged on in >90 days.");
                }
                if (neverExpireCount > 0)
                {
                    hasIssue = true;
                    sb.AppendLine($"  WARNING: {neverExpireCount} member(s) have PasswordNeverExpires set.");
                }
                if (nestedGroupCount > 0)
                {
                    sb.AppendLine($"  INFO: {nestedGroupCount} nested group(s) detected (review for hidden privilege).");
                }
                foreach (var nested in nestedAccounts.Take(NestedFindingLimit))
                {
                    sb.AppendLine($"  NESTED: {nested.Path}");
                }
                if (nestedAccounts.Count > NestedFindingLimit)
                {
                    sb.AppendLine($"  ... and {nestedAccounts.Count - NestedFindingLimit} more nested member(s); see the evidence.");
                }
            }

            // Check for accounts with adminCount=1 not in expected privileged groups
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[adminCount=1 Orphans]");
            var adminCountQuery = new DirectoryQuery(
                "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
                ["sAMAccountName", "distinguishedName", "objectSid"]);

            int orphanCount = 0;
            foreach (var sr in directory.Search(adminCountQuery, ct))
            {
                ct.ThrowIfCancellationRequested();
                string dn = sr.String("distinguishedName") ?? "";
                if (allPrivMembers.Contains(dn)) continue;
                string sam = sr.String("sAMAccountName") ?? dn;

                // AdminSDHolder protects krbtgt and the built-in Administrator themselves, by SID, so their
                // adminCount=1 is expected whatever they're called.
                var sid = sr.Sid("objectSid");
                if (resolver.Identity.IsTier0(sid))
                {
                    evidence.AppendLine($"  {sam}: protected account (RID {resolver.Identity.Rid(sid)}), adminCount=1 is expected");
                    continue;
                }

                // So are members of the other protected groups, such as Backup Operators.
                if (dn.Length > 0 && resolver.Tier0GroupOf(dn, ct) is { } protectingGroup)
                {
                    evidence.AppendLine($"  {sam}: protected through {protectingGroup}, adminCount=1 is expected");
                    continue;
                }

                orphanCount++;
                evidence.AppendLine($"  {sam} (adminCount=1 but not in expected privileged groups)");
                if (orphanCount <= 20)
                    sb.AppendLine($"  ORPHAN: {sam} has adminCount=1 but is not in a known privileged group.");
            }

            if (orphanCount > 0)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {orphanCount} account(s) with adminCount=1 not in expected privileged groups.");
            }

            sb.Insert(0, $"Total privileged group members: {totalPrivileged}\n");

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }
}

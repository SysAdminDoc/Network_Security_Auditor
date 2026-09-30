namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// CF04 - Former Employee Access: Find stale AD accounts (>90d no logon) with
/// privileged group membership, direct or nested, with groups found by SID. AD-dependent.
/// </summary>
public sealed class CF04_FormerEmployeeCheck : ISecurityCheck
{
    public string Id => "CF04";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public CF04_FormerEmployeeCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal CF04_FormerEmployeeCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    // In priority order: an account in several of these is reported under the first.
    private static readonly WellKnownGroup[] PrivilegedGroups =
    [
        WellKnownGroup.DomainAdmins, WellKnownGroup.EnterpriseAdmins, WellKnownGroup.SchemaAdmins,
        WellKnownGroup.Administrators, WellKnownGroup.AccountOperators, WellKnownGroup.ServerOperators,
        WellKnownGroup.BackupOperators, WellKnownGroup.RemoteDesktopUsers
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Former employee access review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            int stalePrivilegedCount = 0;
            int staleEnabledCount = 0;
            var staleThreshold = DateTime.UtcNow.AddDays(-90);

            evidence.AppendLine("[Stale Account Analysis (>90 days no logon)]");

            var directory = _directory(env);

            // Every account in a privileged group, nested ones included, keyed by DN. Groups are found by SID,
            // so a localized domain ("Domänen-Admins") gives the same answer.
            var resolver = PrivilegedGroupResolver.Create(directory, ct);
            var privileged = new Dictionary<string, (ResolvedGroup Group, GroupMember Member)>(StringComparer.OrdinalIgnoreCase);
            foreach (var wellKnown in PrivilegedGroups)
            {
                ct.ThrowIfCancellationRequested();
                var group = resolver.Resolve(wellKnown, ct);
                foreach (var member in resolver.Members(group, [], ct))
                {
                    if (!member.IsGroup) privileged.TryAdd(member.DistinguishedName, (group, member));
                }
            }

            // Find enabled user accounts with no logon in >90 days
            // FileTime for 90 days ago
            long fileTimeThreshold = staleThreshold.ToFileTimeUtc();

            var query = new DirectoryQuery(
                $"(&(objectCategory=person)(objectClass=user)" +
                $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                $"(|(lastLogonTimestamp<={fileTimeThreshold})(!(lastLogonTimestamp=*))))",
                ["sAMAccountName", "lastLogonTimestamp", "whenCreated", "distinguishedName"]);

            ct.ThrowIfCancellationRequested();
            int newAccountCount = 0;

            foreach (var sr in directory.Search(query, ct))
            {
                ct.ThrowIfCancellationRequested();

                string sam = sr.String("sAMAccountName") ?? "";
                long lastLogon = sr.Long("lastLogonTimestamp");

                // Never logged on and created inside the idle window: a new hire who hasn't signed in yet,
                // not a former employee.
                if (lastLogon <= 0 && sr.Time("whenCreated") is { } created && created > staleThreshold)
                {
                    newAccountCount++;
                    evidence.AppendLine($"  NEW, NOT STALE: {sam} | Created: {created:yyyy-MM-dd} | no logon yet");
                    continue;
                }

                staleEnabledCount++;

                // Check if member of any privileged groups
                if (privileged.TryGetValue(sr.String("distinguishedName") ?? "", out var hit))
                {
                    stalePrivilegedCount++;
                    hasIssue = true;

                    string matchedGroup = hit.Group.Name;
                    string via = hit.Member.IsNested ? $" ({hit.Member.Path})" : "";

                    DateTime lastLogonDate = lastLogon > 0
                        ? DateTime.FromFileTimeUtc(lastLogon)
                        : DateTime.MinValue;

                    evidence.AppendLine($"  STALE PRIVILEGED: {sam} | Group: {matchedGroup} | " +
                        $"LastLogon: {(lastLogon > 0 ? lastLogonDate.ToString("yyyy-MM-dd") : "Never")}" +
                        (hit.Member.IsNested ? $" | Path: {hit.Member.Path}" : ""));

                    if (stalePrivilegedCount <= 20)
                    {
                        sb.AppendLine($"CRITICAL: \"{sam}\" - no logon in >90 days, member of {matchedGroup}{via}. " +
                            "Possible former employee with active privileged access.");
                    }
                }
            }

            evidence.AppendLine($"\n  Total stale enabled accounts: {staleEnabledCount}");
            evidence.AppendLine($"  Stale accounts with privileged group membership: {stalePrivilegedCount}");
            if (newAccountCount > 0)
                evidence.AppendLine($"  Created in the last 90 days with no logon yet (not counted): {newAccountCount}");

            sb.Insert(0, $"Stale account analysis: {staleEnabledCount} enabled accounts with no logon in >90 days, " +
                $"{stalePrivilegedCount} in privileged groups.\n");

            if (stalePrivilegedCount > 0)
            {
                sb.AppendLine($"\nWARNING: {stalePrivilegedCount} stale account(s) retain privileged access. " +
                    "Disable or remove from privileged groups immediately.");
            }

            if (staleEnabledCount > 50)
            {
                sb.AppendLine($"INFO: {staleEnabledCount} total stale enabled accounts. " +
                    "Implement regular account access reviews.");
            }

            var status = hasIssue ? CheckStatus.Fail
                : staleEnabledCount > 20 ? CheckStatus.Partial
                : CheckStatus.Pass;

            return Task.FromResult(new CheckResult
            {
                Status = status,
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

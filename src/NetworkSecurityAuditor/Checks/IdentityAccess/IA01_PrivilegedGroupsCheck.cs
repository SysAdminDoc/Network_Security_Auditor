namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA01 - Privileged Groups Review: Domain Admins, Enterprise Admins, Schema Admins,
/// Administrators. Flags stale members, nested groups, PasswordNeverExpires.
/// </summary>
public sealed class IA01_PrivilegedGroupsCheck : ISecurityCheck
{
    public string Id => "IA01";

    private static readonly string[] PrivilegedGroups =
    [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    ];

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

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry)
            {
                PageSize = 1000
            };

            foreach (var groupName in PrivilegedGroups)
            {
                ct.ThrowIfCancellationRequested();
                evidence.AppendLine($"[{groupName}]");

                searcher.Filter = $"(&(objectClass=group)(cn={groupName}))";
                searcher.PropertiesToLoad.Clear();
                searcher.PropertiesToLoad.AddRange(["distinguishedName", "member"]);

                var groupResult = searcher.FindOne();
                if (groupResult == null)
                {
                    evidence.AppendLine("  Group not found.");
                    continue;
                }

                var members = groupResult.Properties["member"];
                int memberCount = members?.Count ?? 0;
                totalPrivileged += memberCount;
                sb.AppendLine($"{groupName}: {memberCount} member(s).");
                evidence.AppendLine($"  Member count: {memberCount}");

                if (memberCount == 0 || members == null) continue;

                int staleCount = 0;
                int neverExpireCount = 0;
                int nestedGroupCount = 0;

                foreach (string? memberDn in members)
                {
                    if (string.IsNullOrEmpty(memberDn)) continue;
                    ct.ThrowIfCancellationRequested();
                    allPrivMembers.Add(memberDn);

                    try
                    {
                        using var memberEntry = new DirectoryEntry("LDAP://" + EscapeDn(memberDn));
                        memberEntry.RefreshCache(["objectClass", "sAMAccountName", "lastLogonTimestamp",
                            "userAccountControl", "pwdLastSet"]);

                        var objectClasses = memberEntry.Properties["objectClass"];
                        bool isGroup = false;
                        if (objectClasses != null)
                        {
                            foreach (var oc in objectClasses)
                            {
                                if (string.Equals(oc?.ToString(), "group", StringComparison.OrdinalIgnoreCase))
                                {
                                    isGroup = true;
                                    break;
                                }
                            }
                        }

                        string sam = memberEntry.Properties["sAMAccountName"]?.Value?.ToString() ?? memberDn;

                        if (isGroup)
                        {
                            nestedGroupCount++;
                            evidence.AppendLine($"  [NESTED GROUP] {sam}");
                            continue;
                        }

                        var lastLogonVal = memberEntry.Properties["lastLogonTimestamp"]?.Value;
                        var lastLogon = ActiveDirectoryValueConverter.GetFileTimeUtc(lastLogonVal);
                        bool isStale = !lastLogon.HasValue || lastLogon.Value < staleThreshold;
                        if (isStale) staleCount++;

                        // Check PasswordNeverExpires (bit 0x10000 of userAccountControl)
                        int uac = 0;
                        var uacVal = memberEntry.Properties["userAccountControl"]?.Value;
                        if (uacVal is int uacInt)
                            uac = uacInt;
                        bool pwdNeverExpires = (uac & 0x10000) != 0;
                        if (pwdNeverExpires) neverExpireCount++;

                        string flags = "";
                        if (isStale) flags += " [STALE]";
                        if (pwdNeverExpires) flags += " [PwdNeverExpires]";

                        var lastLogonLabel = lastLogon.HasValue ? lastLogon.Value.ToString("yyyy-MM-dd") : "Never";
                        evidence.AppendLine($"  {sam} | LastLogon={lastLogonLabel}{flags}");
                    }
                    catch
                    {
                        evidence.AppendLine($"  {memberDn} (could not read details)");
                    }
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
            }

            // Check for accounts with adminCount=1 not in expected privileged groups
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[adminCount=1 Orphans]");
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "distinguishedName"]);

            int orphanCount = 0;
            using var adminCountResults = searcher.FindAll();
            foreach (SearchResult sr in adminCountResults)
            {
                ct.ThrowIfCancellationRequested();
                string dn = sr.Properties["distinguishedName"][0]?.ToString() ?? "";
                if (!allPrivMembers.Contains(dn))
                {
                    orphanCount++;
                    string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? dn;
                    evidence.AppendLine($"  {sam} (adminCount=1 but not in expected privileged groups)");
                    if (orphanCount <= 20)
                        sb.AppendLine($"  ORPHAN: {sam} has adminCount=1 but is not in a known privileged group.");
                }
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

    private static string EscapeDn(string dn)
    {
        // Forward slashes in DN components must be escaped for LDAP binding
        return dn.Replace("/", "\\/");
    }
}

namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF04 - Former Employee Access: Find stale AD accounts (>90d no logon) with
/// privileged group membership. AD-dependent.
/// </summary>
public sealed class CF04_FormerEmployeeCheck : ISecurityCheck
{
    public string Id => "CF04";

    private static readonly string[] PrivilegedGroups =
    [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Server Operators",
        "Backup Operators", "Remote Desktop Users"
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

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            // Find enabled user accounts with no logon in >90 days
            // FileTime for 90 days ago
            long fileTimeThreshold = staleThreshold.ToFileTimeUtc();

            searcher.Filter = $"(&(objectCategory=person)(objectClass=user)" +
                $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                $"(|(lastLogonTimestamp<={fileTimeThreshold})(!(lastLogonTimestamp=*))))";
            searcher.PropertiesToLoad.AddRange(
                ["sAMAccountName", "lastLogonTimestamp", "memberOf", "whenCreated", "distinguishedName"]);

            ct.ThrowIfCancellationRequested();

            using var results = searcher.FindAll();
            foreach (SearchResult sr in results)
            {
                ct.ThrowIfCancellationRequested();

                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";
                staleEnabledCount++;

                // Check if member of any privileged groups
                var memberOf = sr.Properties["memberOf"];
                bool isPrivileged = false;
                string matchedGroup = "";

                foreach (string groupDn in memberOf)
                {
                    foreach (string pg in PrivilegedGroups)
                    {
                        if (groupDn.Contains($"CN={pg}", StringComparison.OrdinalIgnoreCase))
                        {
                            isPrivileged = true;
                            matchedGroup = pg;
                            break;
                        }
                    }
                    if (isPrivileged) break;
                }

                if (isPrivileged)
                {
                    stalePrivilegedCount++;
                    hasIssue = true;

                    long lastLogon = 0;
                    if (sr.Properties["lastLogonTimestamp"].Count > 0)
                        lastLogon = (long)sr.Properties["lastLogonTimestamp"][0];

                    DateTime lastLogonDate = lastLogon > 0
                        ? DateTime.FromFileTimeUtc(lastLogon)
                        : DateTime.MinValue;

                    evidence.AppendLine($"  STALE PRIVILEGED: {sam} | Group: {matchedGroup} | " +
                        $"LastLogon: {(lastLogon > 0 ? lastLogonDate.ToString("yyyy-MM-dd") : "Never")}");

                    if (stalePrivilegedCount <= 20)
                    {
                        sb.AppendLine($"CRITICAL: \"{sam}\" - no logon in >90 days, member of {matchedGroup}. " +
                            "Possible former employee with active privileged access.");
                    }
                }
            }

            evidence.AppendLine($"\n  Total stale enabled accounts: {staleEnabledCount}");
            evidence.AppendLine($"  Stale accounts with privileged group membership: {stalePrivilegedCount}");

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

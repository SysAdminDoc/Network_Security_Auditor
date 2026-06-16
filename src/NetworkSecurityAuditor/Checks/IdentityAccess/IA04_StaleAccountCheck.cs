namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA04 - Stale Account Review: Enabled AD users with LastLogonDate > 90 days.
/// Reports count, top 20, and flags privileged group membership.
/// </summary>
public sealed class IA04_StaleAccountCheck : ISecurityCheck
{
    public string Id => "IA04";

    private static readonly string[] PrivilegedGroupCNs =
    [
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Server Operators", "Backup Operators"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Stale account review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            // Find enabled user accounts
            // ADS_UF_ACCOUNTDISABLE = 0x2; we want enabled, so NOT disabled
            // lastLogonTimestamp < 90 days ago in FILETIME
            long staleThresholdFt = DateTime.UtcNow.AddDays(-90).ToFileTimeUtc();

            searcher.Filter = $"(&(objectCategory=person)(objectClass=user)" +
                              $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                              $"(lastLogonTimestamp<={staleThresholdFt}))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "lastLogonTimestamp",
                "memberOf", "distinguishedName", "pwdLastSet"]);

            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Stale Accounts (>90 days, enabled)]");

            var staleAccounts = new List<(string Sam, DateTime LastLogon, bool IsPrivileged, string Groups)>();

            using var results = searcher.FindAll();
            foreach (SearchResult sr in results)
            {
                ct.ThrowIfCancellationRequested();
                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                long ts = sr.Properties["lastLogonTimestamp"].Count > 0
                    ? (long)sr.Properties["lastLogonTimestamp"][0] : 0;
                DateTime lastLogon = ts > 0 ? DateTime.FromFileTimeUtc(ts) : DateTime.MinValue;

                // Check privileged group membership
                var privGroups = new List<string>();
                if (sr.Properties["memberOf"] != null)
                {
                    foreach (var g in sr.Properties["memberOf"])
                    {
                        string gStr = g?.ToString() ?? "";
                        foreach (var pg in PrivilegedGroupCNs)
                        {
                            if (gStr.Contains($"CN={pg}", StringComparison.OrdinalIgnoreCase))
                            {
                                privGroups.Add(pg);
                                break;
                            }
                        }
                    }
                }

                staleAccounts.Add((sam, lastLogon, privGroups.Count > 0, string.Join(", ", privGroups)));
            }

            int totalStale = staleAccounts.Count;
            int privilegedStale = staleAccounts.Count(a => a.IsPrivileged);

            sb.AppendLine($"Stale accounts (enabled, no logon in >90 days): {totalStale}");

            if (privilegedStale > 0)
            {
                sb.AppendLine($"CRITICAL: {privilegedStale} stale account(s) have privileged group membership.");
            }

            // Sort by last logon ascending (oldest first), show top 20
            var sorted = staleAccounts.OrderBy(a => a.LastLogon).Take(20).ToList();
            if (sorted.Count > 0)
            {
                sb.AppendLine($"\nTop {sorted.Count} oldest stale accounts:");
                foreach (var (sam, lastLogon, isPriv, groups) in sorted)
                {
                    string logonStr = lastLogon == DateTime.MinValue ? "Never" : lastLogon.ToString("yyyy-MM-dd");
                    string privFlag = isPriv ? $" [PRIVILEGED: {groups}]" : "";
                    sb.AppendLine($"  {sam} | LastLogon={logonStr}{privFlag}");
                    evidence.AppendLine($"  {sam} | LastLogon={logonStr}{privFlag}");
                }
            }

            if (totalStale > 20)
                evidence.AppendLine($"  ... and {totalStale - 20} more stale accounts.");

            bool hasIssue = totalStale > 0;

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? (privilegedStale > 0 ? CheckStatus.Fail : CheckStatus.Partial) : CheckStatus.Pass,
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

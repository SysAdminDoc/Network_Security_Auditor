namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA10 - Inactive Accounts: Enabled AD users with LastLogonDate > 180 days
/// OR never logged on. Reports count and top 20.
/// </summary>
public sealed class IA10_InactiveAccountsCheck : ISecurityCheck
{
    public string Id => "IA10";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Inactive account review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            long inactiveThresholdFt = DateTime.UtcNow.AddDays(-180).ToFileTimeUtc();

            // Part 1: Enabled users with lastLogonTimestamp > 180 days
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Inactive Accounts (>180 days or never logged on)]");

            searcher.Filter = $"(&(objectCategory=person)(objectClass=user)" +
                              $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                              $"(lastLogonTimestamp<={inactiveThresholdFt}))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "lastLogonTimestamp",
                "whenCreated", "distinguishedName"]);

            var inactiveAccounts = new List<(string Sam, DateTime LastLogon, DateTime Created)>();

            using (var oldResults = searcher.FindAll())
            {
                foreach (SearchResult sr in oldResults)
                {
                    ct.ThrowIfCancellationRequested();
                    string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                    long ts = sr.Properties["lastLogonTimestamp"].Count > 0
                        ? (long)sr.Properties["lastLogonTimestamp"][0] : 0;
                    DateTime lastLogon = ts > 0 ? DateTime.FromFileTimeUtc(ts) : DateTime.MinValue;

                    DateTime created = sr.Properties["whenCreated"].Count > 0
                        ? (DateTime)sr.Properties["whenCreated"][0]
                        : DateTime.MinValue;

                    inactiveAccounts.Add((sam, lastLogon, created));
                }
            }

            // Part 2: Enabled users that have NEVER logged on (no lastLogonTimestamp attribute)
            ct.ThrowIfCancellationRequested();
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)" +
                              "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                              "(!(lastLogonTimestamp=*)))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "whenCreated"]);

            using (var neverResults = searcher.FindAll())
            {
                foreach (SearchResult sr in neverResults)
                {
                    ct.ThrowIfCancellationRequested();
                    string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";
                    DateTime created = sr.Properties["whenCreated"].Count > 0
                        ? (DateTime)sr.Properties["whenCreated"][0]
                        : DateTime.MinValue;

                    inactiveAccounts.Add((sam, DateTime.MinValue, created));
                }
            }

            int totalInactive = inactiveAccounts.Count;
            int neverLoggedOn = inactiveAccounts.Count(a => a.LastLogon == DateTime.MinValue);
            int stale180 = totalInactive - neverLoggedOn;

            sb.AppendLine($"Total inactive accounts: {totalInactive}");
            sb.AppendLine($"  Never logged on: {neverLoggedOn}");
            sb.AppendLine($"  Last logon > 180 days ago: {stale180}");

            // Top 20 sorted by oldest logon
            var sorted = inactiveAccounts
                .OrderBy(a => a.LastLogon)
                .ThenBy(a => a.Created)
                .Take(20)
                .ToList();

            if (sorted.Count > 0)
            {
                sb.AppendLine($"\nTop {sorted.Count} most inactive:");
                foreach (var (sam, lastLogon, created) in sorted)
                {
                    string logonStr = lastLogon == DateTime.MinValue ? "Never" : lastLogon.ToString("yyyy-MM-dd");
                    string line = $"  {sam} | LastLogon={logonStr} | Created={created:yyyy-MM-dd}";
                    sb.AppendLine(line);
                    evidence.AppendLine(line);
                }
            }

            if (totalInactive > 20)
                evidence.AppendLine($"  ... and {totalInactive - 20} more inactive accounts.");

            bool hasIssue = totalInactive > 0;

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? (totalInactive > 10 ? CheckStatus.Fail : CheckStatus.Partial) : CheckStatus.Pass,
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

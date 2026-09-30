namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA10 - Inactive Accounts: Enabled AD users with LastLogonDate > 180 days
/// OR never logged on. Reports count and top 20.
/// </summary>
public sealed class IA10_InactiveAccountsCheck : ISecurityCheck
{
    public string Id => "IA10";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA10_InactiveAccountsCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA10_InactiveAccountsCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

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

            var directory = _directory(env);

            long inactiveThresholdFt = DateTime.UtcNow.AddDays(-180).ToFileTimeUtc();

            // Part 1: Enabled users with lastLogonTimestamp > 180 days
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Inactive Accounts (>180 days or never logged on)]");

            var oldQuery = new DirectoryQuery(
                $"(&(objectCategory=person)(objectClass=user)" +
                $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                $"(lastLogonTimestamp<={inactiveThresholdFt}))",
                ["sAMAccountName", "lastLogonTimestamp", "whenCreated", "distinguishedName"]);

            var inactiveAccounts = new List<(string Sam, DateTime LastLogon, DateTime Created)>();

            foreach (var sr in directory.Search(oldQuery, ct))
            {
                ct.ThrowIfCancellationRequested();
                string sam = sr.String("sAMAccountName") ?? "";

                long ts = sr.Long("lastLogonTimestamp");
                DateTime lastLogon = ts > 0 ? DateTime.FromFileTimeUtc(ts) : DateTime.MinValue;

                DateTime created = sr.Time("whenCreated") ?? DateTime.MinValue;

                inactiveAccounts.Add((sam, lastLogon, created));
            }

            // Part 2: Enabled users that have NEVER logged on (no lastLogonTimestamp attribute)
            ct.ThrowIfCancellationRequested();
            var neverQuery = new DirectoryQuery(
                "(&(objectCategory=person)(objectClass=user)" +
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                "(!(lastLogonTimestamp=*)))",
                ["sAMAccountName", "whenCreated"]);

            foreach (var sr in directory.Search(neverQuery, ct))
            {
                ct.ThrowIfCancellationRequested();
                string sam = sr.String("sAMAccountName") ?? "";
                DateTime created = sr.Time("whenCreated") ?? DateTime.MinValue;

                inactiveAccounts.Add((sam, DateTime.MinValue, created));
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

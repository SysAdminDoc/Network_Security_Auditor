namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA07 - Shared/Generic Accounts: Search AD for accounts matching shared/generic
/// naming patterns. Report name, enabled status, password age, last logon.
/// </summary>
public sealed class IA07_SharedAccountsCheck : ISecurityCheck
{
    public string Id => "IA07";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA07_SharedAccountsCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA07_SharedAccountsCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    private static readonly string[] SharedPatterns =
    [
        "shared", "generic", "admin", "scanner", "reception", "kiosk",
        "training", "test", "temp"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Shared account review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            var directory = _directory(env);

            evidence.AppendLine("[Shared/Generic Account Scan]");

            // Deduplicate by DN since patterns may overlap
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var accounts = new List<(string Sam, bool Enabled, int PwdAgeDays, string LastLogon, string Pattern)>();

            foreach (var pattern in SharedPatterns)
            {
                ct.ThrowIfCancellationRequested();
                var query = new DirectoryQuery(
                    $"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{pattern}*))",
                    ["sAMAccountName", "distinguishedName", "userAccountControl", "pwdLastSet", "lastLogonTimestamp"]);

                foreach (var sr in directory.Search(query, ct))
                {
                    string dn = sr.String("distinguishedName") ?? "";
                    if (!seen.Add(dn)) continue;

                    string sam = sr.String("sAMAccountName") ?? "";

                    int uac = sr.Int("userAccountControl");
                    bool enabled = (uac & 0x2) == 0;

                    long pwdTs = sr.Long("pwdLastSet");
                    int pwdAge = pwdTs > 0 ? (int)(DateTime.UtcNow - DateTime.FromFileTimeUtc(pwdTs)).TotalDays : -1;

                    long logonTs = sr.Long("lastLogonTimestamp");
                    string lastLogon = logonTs > 0
                        ? DateTime.FromFileTimeUtc(logonTs).ToString("yyyy-MM-dd")
                        : "Never";

                    accounts.Add((sam, enabled, pwdAge, lastLogon, pattern));
                }
            }

            sb.AppendLine($"Shared/generic accounts found: {accounts.Count}");

            int enabledCount = accounts.Count(a => a.Enabled);
            int oldPwdCount = accounts.Count(a => a.Enabled && a.PwdAgeDays > 180);

            if (enabledCount > 0)
            {
                hasIssue = true;
                sb.AppendLine($"  Enabled shared accounts: {enabledCount}");
            }
            if (oldPwdCount > 0)
            {
                sb.AppendLine($"  Enabled with password > 180 days old: {oldPwdCount}");
            }

            foreach (var (sam, enabled, pwdAge, lastLogon, pattern) in accounts.Take(30))
            {
                string line = $"  {sam} | Enabled={enabled} | PwdAge={pwdAge}d | LastLogon={lastLogon} | Match={pattern}";
                evidence.AppendLine(line);
            }

            if (accounts.Count > 30)
                evidence.AppendLine($"  ... and {accounts.Count - 30} more.");

            if (accounts.Count == 0)
                sb.AppendLine("No shared/generic accounts detected matching common naming patterns.");

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

namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA02 - Service Account Audit: Kerberoastable SPNs, password age, DA membership,
/// naming patterns, gMSA adoption.
/// </summary>
public sealed class IA02_ServiceAccountCheck : ISecurityCheck
{
    public string Id => "IA02";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA02_ServiceAccountCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA02_ServiceAccountCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    private static readonly string[] ServicePatterns =
    [
        "svc", "service", "sql", "backup", "batch", "task", "scan", "agent"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Service account audit requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            var directory = _directory(env);

            // 1. Find Kerberoastable accounts (users with SPNs set)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Kerberoastable Accounts (SPN set)]");
            var spnQuery = new DirectoryQuery(
                "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "memberOf", "userAccountControl"]);

            int kerberoastable = 0;
            int oldPassword = 0;
            int inDomainAdmins = 0;

            foreach (var sr in directory.Search(spnQuery, ct))
            {
                ct.ThrowIfCancellationRequested();
                kerberoastable++;
                string sam = sr.String("sAMAccountName") ?? "";

                // Password age
                long pwdLastSet = sr.Long("pwdLastSet");
                DateTime pwdDate = pwdLastSet > 0 ? DateTime.FromFileTimeUtc(pwdLastSet) : DateTime.MinValue;
                int pwdAgeDays = pwdLastSet > 0 ? (int)(DateTime.UtcNow - pwdDate).TotalDays : -1;

                bool isPwdOld = pwdAgeDays > 365;
                if (isPwdOld) oldPassword++;

                // Check Domain Admins membership
                bool isDa = false;
                foreach (var g in sr.Strings("memberOf"))
                {
                    if (g.Contains("CN=Domain Admins", StringComparison.OrdinalIgnoreCase))
                    {
                        isDa = true;
                        inDomainAdmins++;
                        break;
                    }
                }

                // First SPN for evidence
                string firstSpn = sr.String("servicePrincipalName") ?? "";

                string flags = "";
                if (isPwdOld) flags += " [PWD>" + pwdAgeDays + "d]";
                if (isDa) flags += " [DOMAIN ADMIN]";

                evidence.AppendLine($"  {sam} | SPN={firstSpn} | PwdAge={pwdAgeDays}d{flags}");
            }

            sb.AppendLine($"Kerberoastable accounts (user with SPN): {kerberoastable}");
            if (kerberoastable > 0) hasIssue = true;

            if (oldPassword > 0)
            {
                hasIssue = true;
                sb.AppendLine($"  CRITICAL: {oldPassword} SPN account(s) have passwords older than 1 year.");
            }
            if (inDomainAdmins > 0)
            {
                hasIssue = true;
                sb.AppendLine($"  CRITICAL: {inDomainAdmins} SPN account(s) are in Domain Admins (Kerberoast → DA compromise).");
            }

            // 2. Check for naming-pattern service accounts
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Service Account Naming Patterns]");
            int patternMatches = 0;
            foreach (var pattern in ServicePatterns)
            {
                ct.ThrowIfCancellationRequested();
                var patternQuery = new DirectoryQuery(
                    $"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{pattern}*))",
                    ["sAMAccountName", "pwdLastSet", "userAccountControl"]);

                foreach (var sr in directory.Search(patternQuery, ct))
                {
                    string sam = sr.String("sAMAccountName") ?? "";
                    int uac = sr.Int("userAccountControl");
                    bool enabled = (uac & 0x2) == 0; // ADS_UF_ACCOUNTDISABLE = 0x2

                    long pwdTs = sr.Long("pwdLastSet");
                    int pwdAge = pwdTs > 0 ? (int)(DateTime.UtcNow - DateTime.FromFileTimeUtc(pwdTs)).TotalDays : -1;

                    evidence.AppendLine($"  {sam} | Enabled={enabled} | PwdAge={pwdAge}d | Pattern={pattern}");
                    patternMatches++;
                }
            }
            sb.AppendLine($"Service-pattern accounts found: {patternMatches}");

            // 3. gMSA adoption
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Group Managed Service Accounts (gMSA)]");
            var gmsaQuery = new DirectoryQuery(
                "(objectClass=msDS-GroupManagedServiceAccount)",
                ["sAMAccountName", "msDS-ManagedPasswordInterval"]);

            int gmsaCount = 0;
            foreach (var sr in directory.Search(gmsaQuery, ct))
            {
                gmsaCount++;
                string sam = sr.String("sAMAccountName") ?? "";
                evidence.AppendLine($"  {sam}");
            }

            sb.AppendLine($"gMSA accounts: {gmsaCount}");
            if (gmsaCount == 0 && kerberoastable > 0)
            {
                sb.AppendLine("  RECOMMENDATION: No gMSAs detected. Consider migrating service accounts to gMSA for automatic password rotation.");
            }

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

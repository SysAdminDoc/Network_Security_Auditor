namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA02 - Service Account Audit: Kerberoastable SPNs, password age, DA membership,
/// naming patterns, gMSA adoption.
/// </summary>
public sealed class IA02_ServiceAccountCheck : ISecurityCheck
{
    public string Id => "IA02";

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

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            // 1. Find Kerberoastable accounts (users with SPNs set)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Kerberoastable Accounts (SPN set)]");
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "servicePrincipalName",
                "pwdLastSet", "memberOf", "userAccountControl"]);

            int kerberoastable = 0;
            int oldPassword = 0;
            int inDomainAdmins = 0;

            using var spnResults = searcher.FindAll();
            foreach (SearchResult sr in spnResults)
            {
                ct.ThrowIfCancellationRequested();
                kerberoastable++;
                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                // Password age
                long pwdLastSet = 0;
                if (sr.Properties["pwdLastSet"].Count > 0)
                    pwdLastSet = (long)sr.Properties["pwdLastSet"][0];
                DateTime pwdDate = pwdLastSet > 0 ? DateTime.FromFileTimeUtc(pwdLastSet) : DateTime.MinValue;
                int pwdAgeDays = pwdLastSet > 0 ? (int)(DateTime.UtcNow - pwdDate).TotalDays : -1;

                bool isPwdOld = pwdAgeDays > 365;
                if (isPwdOld) oldPassword++;

                // Check Domain Admins membership
                bool isDa = false;
                if (sr.Properties["memberOf"] != null)
                {
                    foreach (var g in sr.Properties["memberOf"])
                    {
                        if (g?.ToString()?.Contains("CN=Domain Admins", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            isDa = true;
                            inDomainAdmins++;
                            break;
                        }
                    }
                }

                // First SPN for evidence
                string firstSpn = sr.Properties["servicePrincipalName"].Count > 0
                    ? sr.Properties["servicePrincipalName"][0]?.ToString() ?? ""
                    : "";

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
                searcher.Filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{pattern}*))";
                searcher.PropertiesToLoad.Clear();
                searcher.PropertiesToLoad.AddRange(["sAMAccountName", "pwdLastSet", "userAccountControl"]);

                using var patResults = searcher.FindAll();
                foreach (SearchResult sr in patResults)
                {
                    string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";
                    int uac = sr.Properties["userAccountControl"].Count > 0
                        ? (int)sr.Properties["userAccountControl"][0] : 0;
                    bool enabled = (uac & 0x2) == 0; // ADS_UF_ACCOUNTDISABLE = 0x2

                    long pwdTs = sr.Properties["pwdLastSet"].Count > 0
                        ? (long)sr.Properties["pwdLastSet"][0] : 0;
                    int pwdAge = pwdTs > 0 ? (int)(DateTime.UtcNow - DateTime.FromFileTimeUtc(pwdTs)).TotalDays : -1;

                    evidence.AppendLine($"  {sam} | Enabled={enabled} | PwdAge={pwdAge}d | Pattern={pattern}");
                    patternMatches++;
                }
            }
            sb.AppendLine($"Service-pattern accounts found: {patternMatches}");

            // 3. gMSA adoption
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Group Managed Service Accounts (gMSA)]");
            searcher.Filter = "(objectClass=msDS-GroupManagedServiceAccount)";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "msDS-ManagedPasswordInterval"]);

            int gmsaCount = 0;
            using var gmsaResults = searcher.FindAll();
            foreach (SearchResult sr in gmsaResults)
            {
                gmsaCount++;
                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";
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

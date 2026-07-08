namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA05 - Password Policy Audit: Default Domain Password Policy benchmarks
/// (MinLength >= 12, MaxAge <= 90d, History >= 12, Complexity, Lockout >= 5).
/// Also checks for fine-grained password policies (PSOs).
/// </summary>
public sealed class IA05_PasswordPolicyCheck : ISecurityCheck
{
    public string Id => "IA05";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Password policy audit requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            rootEntry.RefreshCache([
                "minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                "pwdProperties", "lockoutThreshold", "lockoutDuration",
                "lockOutObservationWindow"
            ]);

            evidence.AppendLine("[Default Domain Password Policy]");

            // Min password length
            int minLen = GetIntProperty(rootEntry, "minPwdLength");
            evidence.AppendLine($"  minPwdLength = {minLen}");
            if (minLen < 12)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: Minimum password length is {minLen} (recommended >= 12).");
            }
            else
            {
                sb.AppendLine($"PASS: Minimum password length is {minLen}.");
            }

            // Max password age (stored as negative 100-nanosecond intervals)
            long maxPwdAgeTicks = GetLongProperty(rootEntry, "maxPwdAge");
            int maxPwdAgeDays = maxPwdAgeTicks != 0
                ? (int)(Math.Abs(maxPwdAgeTicks) / TimeSpan.TicksPerDay)
                : 0;
            evidence.AppendLine($"  maxPwdAge = {maxPwdAgeTicks} ({maxPwdAgeDays} days)");

            if (maxPwdAgeDays == 0)
            {
                hasIssue = true;
                sb.AppendLine("FAIL: Maximum password age is set to 0 (passwords never expire).");
            }
            else if (maxPwdAgeDays > 90)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: Maximum password age is {maxPwdAgeDays} days (recommended <= 90).");
            }
            else
            {
                sb.AppendLine($"PASS: Maximum password age is {maxPwdAgeDays} days.");
            }

            // Password history
            int historyLen = GetIntProperty(rootEntry, "pwdHistoryLength");
            evidence.AppendLine($"  pwdHistoryLength = {historyLen}");
            if (historyLen < 12)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: Password history count is {historyLen} (recommended >= 12).");
            }
            else
            {
                sb.AppendLine($"PASS: Password history count is {historyLen}.");
            }

            // Complexity (pwdProperties bit 1 = DOMAIN_PASSWORD_COMPLEX)
            int pwdProps = GetIntProperty(rootEntry, "pwdProperties");
            bool complexityEnabled = (pwdProps & 1) != 0;
            evidence.AppendLine($"  pwdProperties = {pwdProps} (complexity={(complexityEnabled ? "on" : "off")})");

            if (!complexityEnabled)
            {
                hasIssue = true;
                sb.AppendLine("FAIL: Password complexity is NOT enabled.");
            }
            else
            {
                sb.AppendLine("PASS: Password complexity is enabled.");
            }

            // Lockout threshold
            int lockoutThreshold = GetIntProperty(rootEntry, "lockoutThreshold");
            evidence.AppendLine($"  lockoutThreshold = {lockoutThreshold}");
            if (lockoutThreshold == 0)
            {
                hasIssue = true;
                sb.AppendLine("FAIL: Account lockout is DISABLED (lockoutThreshold=0). Brute-force risk.");
            }
            else if (lockoutThreshold < 5)
            {
                sb.AppendLine($"WARNING: Lockout threshold is {lockoutThreshold} (very aggressive, may cause lockouts).");
            }
            else
            {
                sb.AppendLine($"PASS: Lockout threshold is {lockoutThreshold}.");
            }

            // Lockout duration
            long lockoutDurTicks = GetLongProperty(rootEntry, "lockoutDuration");
            int lockoutDurMin = lockoutDurTicks != 0
                ? (int)(Math.Abs(lockoutDurTicks) / TimeSpan.TicksPerMinute)
                : 0;
            evidence.AppendLine($"  lockoutDuration = {lockoutDurTicks} ({lockoutDurMin} min)");
            if (lockoutThreshold > 0)
            {
                if (lockoutDurMin < 15)
                    sb.AppendLine($"WARNING: Lockout duration is only {lockoutDurMin} minutes (consider >= 15).");
                else
                    sb.AppendLine($"PASS: Lockout duration is {lockoutDurMin} minutes.");
            }

            // Fine-grained password policies (PSOs)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Fine-Grained Password Policies (PSO)]");
            try
            {
                string domainDn = rootEntry.Properties["distinguishedName"]?.Value?.ToString() ?? "";
                string psoCn = $"LDAP://CN=Password Settings Container,CN=System,{domainDn}";
                using var psoContainer = new DirectoryEntry(psoCn);
                using var psoSearcher = new DirectorySearcher(psoContainer)
                {
                    Filter = "(objectClass=msDS-PasswordSettings)",
                    PageSize = 100
                };
                psoSearcher.PropertiesToLoad.AddRange(["cn", "msDS-PasswordSettingsPrecedence",
                    "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge"]);

                int psoCount = 0;
                using var psoResults = psoSearcher.FindAll();
                foreach (SearchResult pso in psoResults)
                {
                    psoCount++;
                    string cn = pso.Properties["cn"].Count > 0 ? pso.Properties["cn"][0]?.ToString() ?? "" : "";
                    int precedence = pso.Properties["msDS-PasswordSettingsPrecedence"].Count > 0
                        ? (int)pso.Properties["msDS-PasswordSettingsPrecedence"][0] : 0;
                    int psoMinLen = pso.Properties["msDS-MinimumPasswordLength"].Count > 0
                        ? (int)pso.Properties["msDS-MinimumPasswordLength"][0] : 0;
                    evidence.AppendLine($"  PSO: {cn} | Precedence={precedence} | MinLen={psoMinLen}");
                }

                sb.AppendLine($"\nFine-grained password policies (PSOs): {psoCount}");
                if (psoCount > 0)
                    sb.AppendLine("  INFO: PSOs override the default policy for targeted users/groups. Review individually.");
            }
            catch
            {
                evidence.AppendLine("  Could not query PSO container (may not exist or access denied).");
                sb.AppendLine("Fine-grained password policies: could not query.");
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

    private static int GetIntProperty(DirectoryEntry entry, string name)
    {
        try
        {
            var val = entry.Properties[name]?.Value;
            if (val == null) return 0;
            return Convert.ToInt32(val);
        }
        catch { return 0; }
    }

    private static long GetLongProperty(DirectoryEntry entry, string name)
    {
        try
        {
            var val = entry.Properties[name]?.Value;
            if (val == null) return 0;
            return ActiveDirectoryValueConverter.GetLargeIntegerValue(val);
        }
        catch { return 0; }
    }
}

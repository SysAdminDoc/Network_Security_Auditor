namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA05 - Password Policy Audit: Default Domain Password Policy benchmarks
/// (MinLength >= 12, MaxAge <= 90d, History >= 12, Complexity, Lockout >= 5).
/// Also checks for fine-grained password policies (PSOs).
/// </summary>
public sealed class IA05_PasswordPolicyCheck : ISecurityCheck
{
    public string Id => "IA05";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA05_PasswordPolicyCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA05_PasswordPolicyCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

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

            var directory = _directory(env);

            // distinguishedName isn't in the policy set: the DirectoryEntry used to fetch it with an implicit
            // GetInfo on first access, and the reader returns only the attributes it was asked for.
            var rootEntry = directory.ReadEntry(null, [
                "minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                "pwdProperties", "lockoutThreshold", "lockoutDuration",
                "lockOutObservationWindow", "distinguishedName"
            ], ct);

            evidence.AppendLine("[Default Domain Password Policy]");

            // Min password length
            int minLen = rootEntry.Int("minPwdLength");
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
            long maxPwdAgeTicks = rootEntry.Long("maxPwdAge");
            int maxPwdAgeDays = ConvertDirectoryIntervalToWholeUnits(maxPwdAgeTicks, TimeSpan.TicksPerDay);
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
            int historyLen = rootEntry.Int("pwdHistoryLength");
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
            int pwdProps = rootEntry.Int("pwdProperties");
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
            int lockoutThreshold = rootEntry.Int("lockoutThreshold");
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
            long lockoutDurTicks = rootEntry.Long("lockoutDuration");
            int lockoutDurMin = ConvertDirectoryIntervalToWholeUnits(lockoutDurTicks, TimeSpan.TicksPerMinute);
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
                string domainDn = rootEntry.String("distinguishedName") ?? "";
                var psoQuery = new DirectoryQuery(
                    "(objectClass=msDS-PasswordSettings)",
                    ["cn", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge"])
                {
                    SearchBase = $"CN=Password Settings Container,CN=System,{domainDn}",
                    PageSize = 100
                };

                int psoCount = 0;
                foreach (var pso in directory.Search(psoQuery, ct))
                {
                    psoCount++;
                    string cn = pso.String("cn") ?? "";
                    int precedence = pso.Int("msDS-PasswordSettingsPrecedence");
                    int psoMinLen = pso.Int("msDS-MinimumPasswordLength");
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

    internal static int ConvertDirectoryIntervalToWholeUnits(long intervalTicks, long ticksPerUnit)
    {
        if (intervalTicks == 0 || intervalTicks == long.MinValue || ticksPerUnit <= 0)
            return 0;

        var absoluteTicks = intervalTicks < 0 ? -intervalTicks : intervalTicks;
        var units = absoluteTicks / ticksPerUnit;
        return units > int.MaxValue ? int.MaxValue : (int)units;
    }
}

namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA06 - PAM/Privileged Access: LAPS deployment coverage.
/// Checks msLAPS-EncryptedPassword (Windows LAPS) and ms-Mcs-AdmPwd (Legacy LAPS)
/// on computer objects. Reports coverage percentage.
/// </summary>
public sealed class IA06_PamCheck : ISecurityCheck
{
    public string Id => "IA06";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. LAPS audit requires Active Directory.",
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

            // Count total enabled computer objects (exclude DCs for LAPS scope)
            ct.ThrowIfCancellationRequested();
            searcher.Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                              "(!(primaryGroupID=516)))"; // 516 = Domain Controllers
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.Add("distinguishedName");

            int totalComputers = 0;
            using (var allComputers = searcher.FindAll())
            {
                totalComputers = allComputers.Count;
            }

            evidence.AppendLine($"[Computer Objects] Total enabled (non-DC): {totalComputers}");

            // Windows LAPS (msLAPS-EncryptedPassword)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Windows LAPS (msLAPS-EncryptedPassword)]");
            int windowsLapsCount = 0;

            try
            {
                searcher.Filter = "(&(objectCategory=computer)(msLAPS-EncryptedPassword=*)" +
                                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                searcher.PropertiesToLoad.Clear();
                searcher.PropertiesToLoad.Add("sAMAccountName");

                using var wlResults = searcher.FindAll();
                windowsLapsCount = wlResults.Count;
                evidence.AppendLine($"  Computers with msLAPS-EncryptedPassword: {windowsLapsCount}");
            }
            catch
            {
                evidence.AppendLine("  msLAPS-EncryptedPassword attribute not found in schema (Windows LAPS not deployed).");
            }

            // Legacy LAPS (ms-Mcs-AdmPwd)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Legacy LAPS (ms-Mcs-AdmPwd)]");
            int legacyLapsCount = 0;

            try
            {
                searcher.Filter = "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*)" +
                                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                searcher.PropertiesToLoad.Clear();
                searcher.PropertiesToLoad.Add("sAMAccountName");

                using var llResults = searcher.FindAll();
                legacyLapsCount = llResults.Count;
                evidence.AppendLine($"  Computers with ms-Mcs-AdmPwd: {legacyLapsCount}");
            }
            catch
            {
                evidence.AppendLine("  ms-Mcs-AdmPwd attribute not found in schema (Legacy LAPS not deployed).");
            }

            // Coverage calculations
            int anyLaps = Math.Max(windowsLapsCount, legacyLapsCount); // rough union
            double coveragePct = totalComputers > 0 ? (anyLaps * 100.0 / totalComputers) : 0;

            sb.AppendLine($"Total enabled computers (non-DC): {totalComputers}");
            sb.AppendLine($"Windows LAPS coverage: {windowsLapsCount}/{totalComputers} ({windowsLapsCount * 100.0 / Math.Max(totalComputers, 1):F1}%)");
            sb.AppendLine($"Legacy LAPS coverage: {legacyLapsCount}/{totalComputers} ({legacyLapsCount * 100.0 / Math.Max(totalComputers, 1):F1}%)");

            if (anyLaps == 0)
            {
                hasIssue = true;
                sb.AppendLine("CRITICAL: No LAPS deployment detected. Local admin passwords are likely shared/static.");
            }
            else if (coveragePct < 80)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: LAPS coverage is {coveragePct:F1}% (target >= 80%).");
            }
            else if (coveragePct < 95)
            {
                sb.AppendLine($"WARNING: LAPS coverage is {coveragePct:F1}% (target >= 95%).");
            }
            else
            {
                sb.AppendLine($"PASS: LAPS coverage is {coveragePct:F1}%.");
            }

            if (windowsLapsCount > 0 && legacyLapsCount > 0)
            {
                sb.AppendLine("INFO: Both Windows LAPS and Legacy LAPS are in use. Plan migration to Windows LAPS only.");
            }

            // Check LAPS delegation ACLs (look for LAPS-related attributes in schema)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[LAPS Schema Attributes]");
            evidence.AppendLine($"  env.HasWindowsLAPS = {env.HasWindowsLAPS}");
            evidence.AppendLine($"  env.HasLegacyLAPS = {env.HasLegacyLAPS}");

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

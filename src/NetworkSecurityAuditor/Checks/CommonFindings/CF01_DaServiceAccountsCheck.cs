namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.DirectoryServices;
using System.IO;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF01 - DA Service Accounts + ADCS: Check Domain Admins for service accounts.
/// Check for gMSA adoption. Check GPP passwords in SYSVOL. Basic ADCS check.
/// AD-dependent.
/// </summary>
public sealed class CF01_DaServiceAccountsCheck : ISecurityCheck
{
    public string Id => "CF01";
    internal const long MaxGppFileBytes = 1_048_576;
    internal const int MaxGppFilesToInspect = 5_000;

    private static readonly string[] ServiceAccountIndicators =
    [
        "svc", "service", "sql", "backup", "scan", "app", "task",
        "batch", "agent", "monitor", "scheduler", "iis", "exchange"
    ];

    private static readonly string[] GppPreferenceFiles =
    [
        "Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml", "Drives.xml"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. DA service account review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Check Domain Admins for service account patterns
            ct.ThrowIfCancellationRequested();
            CheckDaServiceAccounts(env, sb, evidence, ref hasIssue, ct);

            // 2. Check for gMSA adoption
            ct.ThrowIfCancellationRequested();
            CheckGmsaAdoption(env, sb, evidence, ct);

            // 3. Check for GPP password remnants (Groups.xml in SYSVOL)
            ct.ThrowIfCancellationRequested();
            CheckGppPasswords(env, sb, evidence, ref hasIssue, ct);

            // 4. Basic ADCS check
            ct.ThrowIfCancellationRequested();
            CheckAdcs(env, sb, evidence, ct);

            if (!hasIssue)
                sb.Insert(0, "No critical service account issues detected in Domain Admins.\n");
            else
                sb.Insert(0, "Service account security issues detected.\n");

            var status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass;

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

    private static void CheckDaServiceAccounts(EnvironmentInfo env, StringBuilder sb,
        StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("[Domain Admins - Service Account Check]");

        try
        {
            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(&(objectClass=group)(cn=Domain Admins))",
                PageSize = 1000
            };
            searcher.PropertiesToLoad.AddRange(["member"]);

            var result = searcher.FindOne();
            if (result == null)
            {
                evidence.AppendLine("  Domain Admins group not found.");
                return;
            }

            var members = result.Properties["member"];
            int svcAccountCount = 0;

            foreach (string memberDn in members)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var memberEntry = new DirectoryEntry("LDAP://" + memberDn.Replace("/", "\\/"));
                    memberEntry.RefreshCache(["sAMAccountName", "servicePrincipalName", "userAccountControl"]);

                    string sam = memberEntry.Properties["sAMAccountName"]?.Value?.ToString() ?? "";

                    // Check if it looks like a service account
                    bool isService = ServiceAccountIndicators.Any(i =>
                        sam.Contains(i, StringComparison.OrdinalIgnoreCase));

                    // Check for SPN (service accounts typically have SPNs)
                    var spns = memberEntry.Properties["servicePrincipalName"];
                    bool hasSpn = spns?.Count > 0;

                    // Check for non-interactive flags
                    int uac = 0;
                    object? uacVal = memberEntry.Properties["userAccountControl"]?.Value;
                    if (uacVal != null)
                        uac = (int)uacVal;

                    bool pwdNeverExpires = (uac & 0x10000) != 0;

                    if (isService || hasSpn)
                    {
                        svcAccountCount++;
                        hasIssue = true;

                        string flags = "";
                        if (hasSpn) flags += " [HasSPN]";
                        if (pwdNeverExpires) flags += " [PwdNeverExpires]";

                        evidence.AppendLine($"  SERVICE ACCOUNT IN DA: {sam}{flags}");
                        sb.AppendLine($"CRITICAL: Likely service account \"{sam}\" is in Domain Admins.{flags}");
                    }
                }
                catch
                {
                    evidence.AppendLine($"  Could not read: {memberDn}");
                }
            }

            evidence.AppendLine($"  Service accounts in DA: {svcAccountCount}");

            if (svcAccountCount > 0)
            {
                sb.AppendLine("Recommendation: Remove service accounts from Domain Admins. " +
                    "Grant only the minimum required permissions. Use gMSA where possible.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  LDAP error: {ex.Message}");
        }
    }

    private static void CheckGmsaAdoption(EnvironmentInfo env, StringBuilder sb,
        StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[Group Managed Service Accounts (gMSA)]");

        try
        {
            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(objectClass=msDS-GroupManagedServiceAccount)",
                PageSize = 1000
            };
            searcher.PropertiesToLoad.AddRange(["sAMAccountName"]);

            int gmsaCount = 0;
            using var results = searcher.FindAll();
            foreach (SearchResult sr in results)
            {
                ct.ThrowIfCancellationRequested();
                gmsaCount++;
                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";
                if (gmsaCount <= 10)
                    evidence.AppendLine($"  gMSA: {sam}");
            }

            evidence.AppendLine($"  Total gMSAs: {gmsaCount}");

            if (gmsaCount > 0)
                sb.AppendLine($"gMSA adoption: {gmsaCount} group managed service account(s) found (good).");
            else
                sb.AppendLine("INFO: No gMSA accounts found. Consider migrating service accounts to gMSA " +
                    "for automatic password rotation.");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  gMSA query error: {ex.Message}");
        }
    }

    private static void CheckGppPasswords(EnvironmentInfo env, StringBuilder sb,
        StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[GPP Password Check (SYSVOL)]");

        try
        {
            string sysvolPath = $@"\\{env.DomainName}\SYSVOL\{env.DomainName}\Policies";

            if (!Directory.Exists(sysvolPath))
            {
                evidence.AppendLine($"  SYSVOL not accessible: {sysvolPath}");
                return;
            }

            var scan = ScanGppPasswordFiles(sysvolPath, ct);
            foreach (var line in scan.EvidenceLines)
            {
                evidence.AppendLine($"  {line}");
            }

            if (scan.FoundCount > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {scan.FoundCount} GPP file(s) with cpassword found in SYSVOL. " +
                    "These passwords are trivially decryptable (MS14-025). Remove immediately.");
            }
            else
            {
                evidence.AppendLine("  No GPP passwords found.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  SYSVOL scan error: {ex.Message}");
        }
    }

    internal static GppPasswordScanSummary ScanGppPasswordFiles(
        string sysvolPoliciesPath,
        CancellationToken ct)
    {
        var summary = new GppPasswordScanSummary();

        foreach (string policyDir in EnumerateDirectoriesSafe(sysvolPoliciesPath, summary, ct))
        {
            ct.ThrowIfCancellationRequested();

            string[] preferenceRoots =
            [
                Path.Combine(policyDir, "Machine", "Preferences"),
                Path.Combine(policyDir, "User", "Preferences")
            ];

            foreach (string prefsDir in preferenceRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(prefsDir))
                    continue;

                foreach (string gppFile in GppPreferenceFiles)
                {
                    foreach (string file in EnumerateFilesRecursiveSafe(prefsDir, gppFile, summary, ct))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (summary.InspectedCount >= MaxGppFilesToInspect)
                        {
                            summary.Truncated = true;
                            summary.EvidenceLines.Add($"GPP scan stopped after inspecting {MaxGppFilesToInspect} file(s).");
                            return summary;
                        }

                        InspectGppFile(file, summary);
                    }
                }
            }
        }

        return summary;
    }

    private static void InspectGppFile(string file, GppPasswordScanSummary summary)
    {
        try
        {
            var fileInfo = new FileInfo(file);
            if (fileInfo.Length > MaxGppFileBytes)
            {
                summary.SkippedOversizedCount++;
                summary.EvidenceLines.Add($"Skipped oversized GPP file: {file} ({fileInfo.Length} bytes)");
                return;
            }

            summary.InspectedCount++;
            string content = File.ReadAllText(file);
            if (content.Contains("cpassword", StringComparison.OrdinalIgnoreCase) &&
                !content.Contains("cpassword=\"\"", StringComparison.OrdinalIgnoreCase))
            {
                summary.FoundCount++;
                summary.EvidenceLines.Add($"GPP PASSWORD FOUND: {file}");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            summary.SkippedUnreadableCount++;
            summary.EvidenceLines.Add($"Skipped unreadable GPP file: {file} ({ex.Message})");
        }
    }

    private static IEnumerable<string> EnumerateFilesRecursiveSafe(
        string root,
        string fileName,
        GppPasswordScanSummary summary,
        CancellationToken ct)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = pending.Pop();

            foreach (var file in EnumerateFilesSafe(current, fileName, summary))
                yield return file;

            foreach (var directory in EnumerateDirectoriesSafe(current, summary, ct))
                pending.Push(directory);
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(
        string directory,
        string fileName,
        GppPasswordScanSummary summary)
    {
        try
        {
            return Directory.EnumerateFiles(directory, fileName).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            summary.EvidenceLines.Add($"Could not enumerate {directory}: {ex.Message}");
            return [];
        }
    }

    private static IEnumerable<string> EnumerateDirectoriesSafe(
        string directory,
        GppPasswordScanSummary summary,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return Directory.EnumerateDirectories(directory).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            summary.EvidenceLines.Add($"Could not enumerate {directory}: {ex.Message}");
            return [];
        }
    }

    private static void CheckAdcs(EnvironmentInfo env, StringBuilder sb,
        StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[Active Directory Certificate Services (ADCS)]");

        try
        {
            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(objectClass=pKIEnrollmentService)",
                PageSize = 1000
            };
            searcher.PropertiesToLoad.AddRange(["cn", "dNSHostName"]);

            int caCount = 0;
            using var results = searcher.FindAll();
            foreach (SearchResult sr in results)
            {
                ct.ThrowIfCancellationRequested();
                caCount++;
                string cn = sr.Properties["cn"][0]?.ToString() ?? "";
                string dns = sr.Properties.Contains("dNSHostName") && sr.Properties["dNSHostName"].Count > 0
                    ? sr.Properties["dNSHostName"][0]?.ToString() ?? "" : "";

                evidence.AppendLine($"  CA: {cn} ({dns})");
            }

            if (caCount > 0)
            {
                sb.AppendLine($"ADCS: {caCount} Certificate Authority(ies) found. " +
                    "Review certificate templates for ESC1-ESC8 misconfigurations.");
            }
            else
            {
                evidence.AppendLine("  No ADCS enrollment services found.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  ADCS query error: {ex.Message}");
        }
    }

    internal sealed class GppPasswordScanSummary
    {
        public int FoundCount { get; set; }
        public int InspectedCount { get; set; }
        public int SkippedOversizedCount { get; set; }
        public int SkippedUnreadableCount { get; set; }
        public bool Truncated { get; set; }
        public List<string> EvidenceLines { get; } = [];
    }
}

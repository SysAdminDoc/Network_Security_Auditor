namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.IO;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

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

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;
    private readonly Func<EnvironmentInfo, string> _sysvolPoliciesPath;

    public CF01_DaServiceAccountsCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    /// <param name="sysvolPoliciesPath">Where the GPP scan looks; tests point it at a local folder.</param>
    internal CF01_DaServiceAccountsCheck(
        Func<EnvironmentInfo, IDirectoryReader> directory,
        Func<EnvironmentInfo, string>? sysvolPoliciesPath = null)
    {
        _directory = directory;
        _sysvolPoliciesPath = sysvolPoliciesPath ?? (env => $@"\\{env.DomainName}\SYSVOL\{env.DomainName}\Policies");
    }

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
            // Parts of the review that couldn't run. The check never passes with any of them.
            var gaps = new List<string>();

            var directory = _directory(env);

            // 1. Check Domain Admins for service account patterns. This is the core search: when the directory
            //    can't answer it, nothing else CF01 says about the domain can be trusted to be complete.
            ct.ThrowIfCancellationRequested();
            var daReview = CheckDaServiceAccounts(directory, sb, evidence, gaps, ref hasIssue, ct);

            // 2. Check for gMSA adoption
            ct.ThrowIfCancellationRequested();
            CheckGmsaAdoption(directory, sb, evidence, gaps, ct);

            // 3. Check for GPP password remnants (Groups.xml in SYSVOL)
            ct.ThrowIfCancellationRequested();
            CheckGppPasswords(_sysvolPoliciesPath(env), sb, evidence, gaps, ref hasIssue, ct);

            // 4. Basic ADCS check
            ct.ThrowIfCancellationRequested();
            CheckAdcs(directory, sb, evidence, gaps, ct);

            // A confirmed finding stands even when other parts couldn't run.
            CheckStatus status;
            string headline;
            if (hasIssue)
            {
                status = CheckStatus.Fail;
                headline = "Service account security issues detected.";
            }
            else if (daReview.Error is not null)
            {
                status = CheckStatus.Error;
                headline = $"Could not read the directory, so Domain Admins weren't reviewed: {daReview.Error}";
            }
            else if (daReview.GroupNotFound)
            {
                status = CheckStatus.NotAssessed;
                headline = "The Domain Admins group wasn't found (searched by the name \"Domain Admins\"), so its members weren't reviewed.";
            }
            else if (gaps.Count > 0)
            {
                status = CheckStatus.Partial;
                headline = "No service accounts found in Domain Admins, but parts of the review couldn't run.";
            }
            else
            {
                status = CheckStatus.Pass;
                headline = "No critical service account issues detected in Domain Admins.";
            }

            sb.Insert(0, headline + "\n");
            if (gaps.Count > 0)
            {
                sb.AppendLine("\nNot assessed:");
                foreach (var gap in gaps)
                    sb.AppendLine($"  - {gap}");
            }

            return Task.FromResult(new CheckResult
            {
                Status = status,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd(),
                Error = status == CheckStatus.Error ? daReview.Error : null
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    /// <summary>How the Domain Admins review went: an LDAP error, a missing group, or reviewed.</summary>
    private sealed record DaReview(string? Error, bool GroupNotFound);

    private const int MaxUnreadMembersListed = 10;

    private static DaReview CheckDaServiceAccounts(IDirectoryReader directory, StringBuilder sb,
        StringBuilder evidence, List<string> gaps, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("[Domain Admins - Service Account Check]");

        try
        {
            var query = new DirectoryQuery("(&(objectClass=group)(cn=Domain Admins))", ["member"])
            {
                SizeLimit = 1
            };

            var result = directory.Search(query, ct).FirstOrDefault();
            if (result == null)
            {
                evidence.AppendLine("  Domain Admins group not found.");
                gaps.Add("Domain Admins: the group wasn't found by name, so its members weren't reviewed.");
                return new DaReview(null, GroupNotFound: true);
            }

            var members = result.Strings("member");
            int svcAccountCount = 0;
            var unreadMembers = new List<string>();

            foreach (string memberDn in members)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var memberEntry = directory.ReadEntry(memberDn,
                        ["sAMAccountName", "servicePrincipalName", "userAccountControl"], ct);

                    string sam = memberEntry.String("sAMAccountName") ?? "";

                    // Check if it looks like a service account
                    bool isService = ServiceAccountIndicators.Any(i =>
                        sam.Contains(i, StringComparison.OrdinalIgnoreCase));

                    // Check for SPN (service accounts typically have SPNs)
                    bool hasSpn = memberEntry.Has("servicePrincipalName");

                    // Check for non-interactive flags
                    int uac = memberEntry.Int("userAccountControl");

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
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    evidence.AppendLine($"  Could not read: {memberDn}");
                    unreadMembers.Add(memberDn);
                }
            }

            evidence.AppendLine($"  Service accounts in DA: {svcAccountCount}");

            if (svcAccountCount > 0)
            {
                sb.AppendLine("Recommendation: Remove service accounts from Domain Admins. " +
                    "Grant only the minimum required permissions. Use gMSA where possible.");
            }

            if (unreadMembers.Count > 0)
            {
                string more = unreadMembers.Count > MaxUnreadMembersListed ? $"; and {unreadMembers.Count - MaxUnreadMembersListed} more" : "";
                gaps.Add($"{unreadMembers.Count} Domain Admins member(s) could not be read: " +
                    string.Join("; ", unreadMembers.Take(MaxUnreadMembersListed)) + more);
            }
            return new DaReview(null, GroupNotFound: false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  LDAP error: {ex.Message}");
            gaps.Add($"Domain Admins: the directory couldn't be read ({ex.Message}).");
            return new DaReview(ex.Message, GroupNotFound: false);
        }
    }

    private static void CheckGmsaAdoption(IDirectoryReader directory, StringBuilder sb,
        StringBuilder evidence, List<string> gaps, CancellationToken ct)
    {
        evidence.AppendLine("\n[Group Managed Service Accounts (gMSA)]");

        try
        {
            var query = new DirectoryQuery("(objectClass=msDS-GroupManagedServiceAccount)", ["sAMAccountName"]);

            int gmsaCount = 0;
            foreach (var sr in directory.Search(query, ct))
            {
                ct.ThrowIfCancellationRequested();
                gmsaCount++;
                string sam = sr.String("sAMAccountName") ?? "";
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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  gMSA query error: {ex.Message}");
            gaps.Add($"gMSA inventory could not be read ({ex.Message}).");
        }
    }

    private static void CheckGppPasswords(string sysvolPath, StringBuilder sb,
        StringBuilder evidence, List<string> gaps, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[GPP Password Check (SYSVOL)]");

        try
        {
            if (!Directory.Exists(sysvolPath))
            {
                evidence.AppendLine($"  SYSVOL not accessible: {sysvolPath}");
                gaps.Add($"SYSVOL could not be read at {sysvolPath}, so GPP passwords weren't checked.");
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

            var skipped = new List<string>();
            if (scan.SkippedUnreadableCount > 0) skipped.Add($"{scan.SkippedUnreadableCount} unreadable file(s)");
            if (scan.SkippedOversizedCount > 0) skipped.Add($"{scan.SkippedOversizedCount} file(s) over {MaxGppFileBytes} bytes");
            if (scan.EnumerationErrorCount > 0) skipped.Add($"{scan.EnumerationErrorCount} folder(s) that couldn't be listed");
            if (scan.Truncated) skipped.Add($"everything after the first {MaxGppFilesToInspect} files");
            if (skipped.Count > 0)
                gaps.Add($"The GPP password scan skipped {string.Join(", ", skipped)}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  SYSVOL scan error: {ex.Message}");
            gaps.Add($"The SYSVOL scan failed ({ex.Message}), so GPP passwords weren't fully checked.");
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
            summary.EnumerationErrorCount++;
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
            summary.EnumerationErrorCount++;
            summary.EvidenceLines.Add($"Could not enumerate {directory}: {ex.Message}");
            return [];
        }
    }

    private static void CheckAdcs(IDirectoryReader directory, StringBuilder sb,
        StringBuilder evidence, List<string> gaps, CancellationToken ct)
    {
        evidence.AppendLine("\n[Active Directory Certificate Services (ADCS)]");

        try
        {
            var query = new DirectoryQuery("(objectClass=pKIEnrollmentService)", ["cn", "dNSHostName"]);

            int caCount = 0;
            foreach (var sr in directory.Search(query, ct))
            {
                ct.ThrowIfCancellationRequested();
                caCount++;
                string cn = sr.String("cn") ?? "";
                string dns = sr.Has("dNSHostName") ? sr.String("dNSHostName") ?? "" : "";

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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  ADCS query error: {ex.Message}");
            gaps.Add($"AD CS enrollment services could not be read ({ex.Message}).");
        }
    }

    internal sealed class GppPasswordScanSummary
    {
        public int FoundCount { get; set; }
        public int InspectedCount { get; set; }
        public int SkippedOversizedCount { get; set; }
        public int SkippedUnreadableCount { get; set; }
        public bool Truncated { get; set; }
        public int EnumerationErrorCount { get; set; }
        public List<string> EvidenceLines { get; } = [];
    }
}

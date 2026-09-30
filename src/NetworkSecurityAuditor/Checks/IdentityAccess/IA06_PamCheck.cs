namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA06 - PAM/Privileged Access: LAPS deployment coverage.
/// Coverage comes from the password expiration attributes (msLAPS-PasswordExpirationTime for
/// Windows LAPS, ms-Mcs-AdmPwdExpirationTime for legacy LAPS), which Authenticated Users can read
/// by default. The password attributes themselves are confidential and return nothing to an auditor
/// without the LAPS read right, so they're never used to measure coverage.
/// </summary>
public sealed class IA06_PamCheck : ISecurityCheck
{
    internal const string WindowsLapsExpiration = "msLAPS-PasswordExpirationTime";
    internal const string LegacyLapsExpiration = "ms-Mcs-AdmPwdExpirationTime";

    /// <summary>Enabled computers that aren't writable (516) or read-only (521) domain controllers.</summary>
    internal const string PopulationFilter =
        "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
        "(!(primaryGroupID=516))(!(primaryGroupID=521)))";

    // Windows LAPS reads policy from CSP, then GPO, then local configuration.
    private static readonly string[] WindowsLapsPolicyKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Policies\LAPS",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config",
    ];
    private const string LegacyLapsPolicyKey = @"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd";
    private const int MaxUncoveredListed = 10;

    public string Id => "IA06";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA06_PamCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA06_PamCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    internal sealed record LapsComputer(string DistinguishedName, bool WindowsLaps, bool LegacyLaps);

    internal sealed record LapsSnapshot
    {
        /// <summary>Null when computer objects couldn't be searched.</summary>
        public IReadOnlyList<LapsComputer>? Computers { get; init; }
        public string? SearchError { get; init; }
        public bool SearchAccessDenied { get; init; }
        /// <summary>Whether the schema defines the attribute; null when the schema couldn't be read.</summary>
        public bool? WindowsLapsSchema { get; init; }
        public bool? LegacyLapsSchema { get; init; }
        public string? SchemaError { get; init; }
        /// <summary>The auditing machine's Windows LAPS BackupDirectory policy (1 = Entra ID, 2 = Active Directory).</summary>
        public int? LocalBackupDirectory { get; init; }
        public bool LocalLegacyLapsEnabled { get; init; }
    }

    internal sealed record LapsAssessment(CheckStatus Status, string Findings, string Evidence, int Covered, int Total, string? Error);

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
            var assessment = Assess(CollectSnapshot(_directory(env), ct));
            return Task.FromResult(new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence,
                Error = assessment.Error
            });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static LapsAssessment Assess(LapsSnapshot snapshot)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();

        evidence.AppendLine("[LAPS Schema Attributes]");
        evidence.AppendLine($"  {WindowsLapsExpiration}: {SchemaText(snapshot.WindowsLapsSchema)}");
        evidence.AppendLine($"  {LegacyLapsExpiration}: {SchemaText(snapshot.LegacyLapsSchema)}");
        if (snapshot.SchemaError is not null)
            evidence.AppendLine($"  Schema couldn't be read: {snapshot.SchemaError}");
        evidence.AppendLine("\n[Auditing Machine LAPS Policy]");
        evidence.AppendLine($"  Windows LAPS BackupDirectory: {BackupDirectoryText(snapshot.LocalBackupDirectory)}");
        evidence.AppendLine($"  Legacy LAPS (AdmPwdEnabled): {(snapshot.LocalLegacyLapsEnabled ? "1" : "not set")}");

        if (snapshot.Computers is null)
        {
            var error = snapshot.SearchError ?? "Computer search failed.";
            evidence.AppendLine($"\n[Computer Objects]\n  Search failed: {error}");
            sb.AppendLine(snapshot.SearchAccessDenied
                ? "NOT ASSESSED: the auditing account was denied access to computer objects, so LAPS coverage can't be measured. " +
                  "It needs Read on computer objects in the domain (Authenticated Users have it by default)."
                : $"NOT ASSESSED: computer objects couldn't be searched ({error}).");
            return new LapsAssessment(CheckStatus.NotAssessed, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd(), 0, 0, error);
        }

        // One object per distinguished name, so a computer with both attributes counts once.
        var computers = snapshot.Computers
            .GroupBy(c => c.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new LapsComputer(g.Key, g.Any(c => c.WindowsLaps), g.Any(c => c.LegacyLaps)))
            .ToList();
        var total = computers.Count;
        var windowsCount = computers.Count(c => c.WindowsLaps);
        var legacyCount = computers.Count(c => c.LegacyLaps);
        var uncovered = computers.Where(c => !c.WindowsLaps && !c.LegacyLaps).ToList();
        var covered = total - uncovered.Count;
        var windowsSchema = snapshot.WindowsLapsSchema ?? (windowsCount > 0 ? true : null);
        var legacySchema = snapshot.LegacyLapsSchema ?? (legacyCount > 0 ? true : null);

        evidence.AppendLine("\n[Computer Objects]");
        evidence.AppendLine($"  Enabled computers (excluding domain controllers): {total}");
        evidence.AppendLine($"  With {WindowsLapsExpiration}: {windowsCount}");
        evidence.AppendLine($"  With {LegacyLapsExpiration}: {legacyCount}");
        evidence.AppendLine($"  With either (union by distinguished name): {covered}");
        if (uncovered.Count > 0 && covered > 0)
        {
            evidence.AppendLine($"  Without a LAPS expiration time (first {Math.Min(uncovered.Count, MaxUncoveredListed)} of {uncovered.Count}):");
            foreach (var c in uncovered.Take(MaxUncoveredListed))
                evidence.AppendLine($"    {c.DistinguishedName}");
        }

        CheckStatus status;
        string? assessmentError = null;

        if (windowsSchema == false && legacySchema == false)
        {
            status = CheckStatus.Fail;
            sb.AppendLine("FAIL: The Active Directory schema has neither the Windows LAPS nor the legacy LAPS attributes, " +
                "so no computer can back up a LAPS password to AD. Local administrator passwords are likely shared or static.");
            sb.AppendLine("  Devices that back up Windows LAPS to Microsoft Entra ID aren't visible to this check.");
        }
        else if (total == 0)
        {
            status = CheckStatus.NotAssessed;
            assessmentError = "No enabled member computers were returned.";
            sb.AppendLine("NOT ASSESSED: the search returned no enabled computers other than domain controllers. " +
                "If the domain has member computers, check that the auditing account can list computer objects.");
        }
        else if (covered == 0 && (snapshot.LocalBackupDirectory == 2 || snapshot.LocalLegacyLapsEnabled))
        {
            // This machine is told to back up to AD, yet no object anywhere shows an expiration time.
            status = CheckStatus.NotAssessed;
            assessmentError = "LAPS expiration attributes appear unreadable to the auditing account.";
            sb.AppendLine($"NOT ASSESSED: this computer has a LAPS policy that backs up to Active Directory, but none of the {total} " +
                "enabled computers shows a LAPS password expiration time. The auditing account most likely can't read it.");
            sb.AppendLine($"  Grant Read Property on {WindowsLapsExpiration} and {LegacyLapsExpiration} for computer objects " +
                "(Authenticated Users have it by default), or rerun as an account that has it.");
        }
        else if (covered == 0)
        {
            status = CheckStatus.Fail;
            sb.AppendLine($"FAIL: The LAPS schema is present, but none of the {total} enabled computers has a LAPS password " +
                "expiration time. LAPS isn't managing local administrator passwords.");
        }
        else
        {
            var coveragePct = covered * 100.0 / total;
            if (coveragePct < 80)
            {
                status = CheckStatus.Fail;
                sb.AppendLine($"FAIL: LAPS coverage is {coveragePct:F1}% ({covered}/{total}, target >= 80%).");
            }
            else if (coveragePct < 95)
            {
                status = CheckStatus.Pass;
                sb.AppendLine($"WARNING: LAPS coverage is {coveragePct:F1}% ({covered}/{total}, target >= 95%).");
            }
            else
            {
                status = CheckStatus.Pass;
                sb.AppendLine($"PASS: LAPS coverage is {coveragePct:F1}% ({covered}/{total}).");
            }
        }

        if (total > 0)
        {
            sb.AppendLine($"Windows LAPS: {windowsCount}/{total} ({windowsCount * 100.0 / total:F1}%)");
            sb.AppendLine($"Legacy LAPS: {legacyCount}/{total} ({legacyCount * 100.0 / total:F1}%)");
        }
        if (windowsCount > 0 && legacyCount > 0)
            sb.AppendLine("INFO: Both Windows LAPS and legacy LAPS are in use. Plan migration to Windows LAPS only.");
        else if (legacyCount > 0)
            sb.AppendLine("INFO: Only legacy LAPS is in use. It stores passwords in cleartext; plan migration to Windows LAPS.");

        return new LapsAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd(), covered, total, assessmentError);
    }

    internal static LapsSnapshot CollectSnapshot(IDirectoryReader directory, CancellationToken ct)
    {
        bool? windowsSchema = null, legacySchema = null;
        string? schemaError = null;
        try
        {
            var rootDse = directory.ReadEntry(DirectoryReader.RootDse, ["schemaNamingContext"], ct);
            var schemaNc = rootDse.First("schemaNamingContext") as string;
            if (!string.IsNullOrWhiteSpace(schemaNc))
            {
                windowsSchema = SchemaHasAttribute(directory, schemaNc, WindowsLapsExpiration, ct);
                legacySchema = SchemaHasAttribute(directory, schemaNc, LegacyLapsExpiration, ct);
            }
            else
            {
                schemaError = "RootDSE returned no schemaNamingContext.";
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
        {
            schemaError = ex.Message.Trim();
        }

        ct.ThrowIfCancellationRequested();
        List<LapsComputer>? computers = null;
        string? searchError = null;
        var accessDenied = false;
        try
        {
            var properties = new List<string> { "distinguishedName" };
            // Unknown attributes are never requested, so a partly extended schema can't break the search.
            if (windowsSchema != false) properties.Add(WindowsLapsExpiration);
            if (legacySchema != false) properties.Add(LegacyLapsExpiration);

            computers = [];
            foreach (var result in directory.Search(new DirectoryQuery(PopulationFilter, properties), ct))
            {
                ct.ThrowIfCancellationRequested();
                var dn = result.String("distinguishedName") ?? result.Path;
                computers.Add(new LapsComputer(
                    dn,
                    HasValue(result, WindowsLapsExpiration),
                    HasValue(result, LegacyLapsExpiration)));
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
        {
            computers = null;
            searchError = ex.Message.Trim();
            accessDenied = IsAccessDenied(ex);
        }

        return new LapsSnapshot
        {
            Computers = computers,
            SearchError = searchError,
            SearchAccessDenied = accessDenied,
            WindowsLapsSchema = windowsSchema,
            LegacyLapsSchema = legacySchema,
            SchemaError = schemaError,
            LocalBackupDirectory = ReadLocalBackupDirectory(),
            LocalLegacyLapsEnabled = RegistryHelper.GetValue<int>(LegacyLapsPolicyKey, "AdmPwdEnabled", 0) == 1,
        };
    }

    internal static bool IsAccessDenied(Exception ex) => ex switch
    {
        UnauthorizedAccessException => true,
        DirectoryServicesCOMException ds when ds.ExtendedError == 5 => true,
        // E_ACCESSDENIED, and LDAP_INSUFFICIENT_RIGHTS (50) wrapped as an ADSI HRESULT.
        COMException com => com.ErrorCode is unchecked((int)0x80070005) or unchecked((int)0x80072098),
        _ => false,
    };

    private static bool SchemaHasAttribute(IDirectoryReader directory, string schemaNc, string ldapDisplayName, CancellationToken ct)
    {
        var query = new DirectoryQuery($"(&(objectClass=attributeSchema)(lDAPDisplayName={ldapDisplayName}))", ["lDAPDisplayName"])
        {
            SearchBase = schemaNc,
            Scope = SearchScope.OneLevel,
            PageSize = 0,
            // Bound on the domain's server, as before the reader seam: across a forest trust the user's own DC
            // doesn't hold this forest's schema.
            OnDomainServer = true,
        };
        return directory.Search(query, ct).Count > 0;
    }

    private static bool HasValue(DirectoryRecord result, string attribute) =>
        result.First(attribute) is { } value && !IsZeroFileTime(value);

    // An expiration time of 0 means LAPS never set a password on that object.
    private static bool IsZeroFileTime(object value) => value switch
    {
        long l => l == 0,
        string s => s.Trim() is "" or "0",
        _ => false,
    };

    private static int? ReadLocalBackupDirectory()
    {
        foreach (var key in WindowsLapsPolicyKeys)
        {
            var value = RegistryHelper.GetValue<int?>(key, "BackupDirectory");
            if (value is not null)
                return value;
        }
        return null;
    }

    private static string SchemaText(bool? present) => present switch
    {
        true => "present",
        false => "not in schema",
        null => "unknown",
    };

    private static string BackupDirectoryText(int? value) => value switch
    {
        null => "not configured",
        0 => "0 (disabled)",
        1 => "1 (Microsoft Entra ID)",
        2 => "2 (Active Directory)",
        _ => value.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
}

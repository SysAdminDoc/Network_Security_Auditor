namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Globalization;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP04 - Patch compliance: OS update recency, whether the OS release still gets updates, and CISA KEV entries
/// newer than this host's updates. The last update date is the newer of Win32_QuickFixEngineering and the
/// Windows Update install history, so hotpatch months (installed without a new baseline) count as patched.
/// </summary>
public sealed class EP04_PatchComplianceCheck : ISecurityCheck
{
    public string Id => "EP04";

    private const int StalePatchDays = 30;

    private readonly Func<EnvironmentInfo, CancellationToken, PatchSnapshot> _collect;
    private readonly KevCatalogService _kev;
    private readonly Func<DateTime> _now;

    public EP04_PatchComplianceCheck() : this(null, null, null) { }

    /// <summary>Test seam: the host snapshot (hotfixes, update history, products), the KEV feed source and the clock.</summary>
    internal EP04_PatchComplianceCheck(
        Func<EnvironmentInfo, CancellationToken, PatchSnapshot>? collect,
        KevCatalogService? kev,
        Func<DateTime>? now)
    {
        _collect = collect ?? CollectSnapshot;
        _kev = kev ?? new KevCatalogService();
        _now = now ?? (() => DateTime.Now);
    }

    internal sealed record HotfixInfo(string HotFixId, DateTime InstalledOn, string Description);

    internal sealed record UpdateHistoryEntry(string Title, DateTime Date);

    internal sealed record PatchSnapshot
    {
        public IReadOnlyList<HotfixInfo> Hotfixes { get; init; } = [];
        public string? HotfixError { get; init; }
        /// <summary>Successful installs from the Windows Update Agent history; null when it couldn't be read.</summary>
        public IReadOnlyList<UpdateHistoryEntry>? UpdateHistory { get; init; }
        public string? UpdateHistoryError { get; init; }
        public string OsCaption { get; init; } = "";
        public int OsBuild { get; init; }
        public string OsVersion { get; init; } = "";
        /// <summary>Separately serviced products for the KEV cross-reference; null means Windows only.</summary>
        public KevProductInventory? Products { get; init; }
        /// <summary>The KEV feed load; null when the cross-reference wasn't attempted.</summary>
        public KevCatalogLoad? Kev { get; init; }
    }

    internal sealed record PatchAssessment(CheckStatus Status, string Findings, string Evidence);

    public async Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var snapshot = _collect(env, ct);
            ct.ThrowIfCancellationRequested();
            var kev = await _kev.LoadAsync(options.NoInternet, ct).ConfigureAwait(false);
            var assessment = Assess(snapshot with { Kev = kev }, DateOnly.FromDateTime(_now()));
            return new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return CheckResult.FromError(Id, ex);
        }
    }

    internal static PatchAssessment Assess(PatchSnapshot snapshot, DateOnly today)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        var hasIssue = false;

        evidence.AppendLine("[Installed Hotfixes (Win32_QuickFixEngineering)]");
        if (snapshot.HotfixError is not null)
            evidence.AppendLine($"  WMI error: {snapshot.HotfixError}");
        foreach (var h in snapshot.Hotfixes)
            evidence.AppendLine($"  {h.HotFixId}: {(h.InstalledOn == DateTime.MinValue ? "date unknown" : FormatDate(h.InstalledOn))}, {h.Description}");
        evidence.AppendLine($"\n[Summary] Total hotfixes returned: {snapshot.Hotfixes.Count}");

        var lastHotfix = snapshot.Hotfixes
            .Where(h => h.InstalledOn != DateTime.MinValue)
            .OrderByDescending(h => h.InstalledOn)
            .FirstOrDefault();
        var osUpdates = (snapshot.UpdateHistory ?? [])
            .Where(u => IsOsQualityUpdate(u.Title, snapshot.OsBuild))
            .OrderByDescending(u => u.Date)
            .ToList();
        var lastOsUpdate = osUpdates.FirstOrDefault();

        evidence.AppendLine("\n[Windows Update History (OS quality updates)]");
        if (snapshot.UpdateHistory is null)
            evidence.AppendLine($"  Couldn't read: {snapshot.UpdateHistoryError ?? "unavailable"}");
        foreach (var u in osUpdates.Take(5))
            evidence.AppendLine($"  {FormatDate(u.Date)}: {u.Title}");

        // The newer of the two sources is the last time this OS was patched.
        var candidates = new List<(DateTime Date, string Label)>();
        if (lastHotfix is not null)
            candidates.Add((lastHotfix.InstalledOn, $"{lastHotfix.HotFixId} (hotfix list)"));
        if (lastOsUpdate is not null)
            candidates.Add((lastOsUpdate.Date.Date, $"{lastOsUpdate.Title} (Windows Update history)"));
        var latest = candidates.OrderByDescending(x => x.Date).FirstOrDefault();

        if (candidates.Count == 0)
        {
            if (snapshot.Hotfixes.Count == 0)
            {
                hasIssue = true;
                sb.AppendLine("WARNING: No hotfix records returned from WMI (Win32_QuickFixEngineering) and no OS update in the Windows Update history.");
                sb.AppendLine("  This may indicate WMI issues or that updates are managed by a non-standard mechanism.");
            }
            else
            {
                sb.AppendLine($"Hotfix count: {snapshot.Hotfixes.Count}, but no install dates could be parsed.");
                sb.AppendLine("WARNING: Cannot determine patch recency without install dates.");
            }
        }
        else
        {
            var daysSince = today.DayNumber - DateOnly.FromDateTime(latest.Date).DayNumber;
            evidence.AppendLine($"\n  Most recent OS update: {latest.Label} on {FormatDate(latest.Date)} ({daysSince} days ago)");
            sb.AppendLine($"Hotfix count: {snapshot.Hotfixes.Count}. Most recent OS update: {latest.Label}, {FormatDate(latest.Date)} ({daysSince}d ago).");
            if (daysSince > StalePatchDays)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: Last OS update is {daysSince} days old (threshold: {StalePatchDays} days). System may be missing security updates.");
            }
        }

        CheckBuildCurrency(snapshot, today, sb, evidence, ref hasIssue);

        DateTime? latestOsDate = candidates.Count == 0 ? null : latest.Date.Date;
        var kev = CrossReferenceKev(snapshot, latestOsDate, today, sb, evidence);

        // Any KEV entry newer than the host's updates is a warning; a ransomware-linked one fails once it's overdue.
        var status = hasIssue || kev.RansomwareOverdue > 0 ? CheckStatus.Fail
            : kev.Hits > 0 ? CheckStatus.Partial
            : CheckStatus.Pass;
        return new PatchAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd());
    }

    private readonly record struct KevOutcome(int Hits, int RansomwareOverdue);

    private static KevOutcome CrossReferenceKev(PatchSnapshot snapshot, DateTime? latestOsDate, DateOnly today, StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[CISA KEV Cross-Reference]");
        var load = snapshot.Kev;
        if (load is null)
        {
            evidence.AppendLine("  Not attempted.");
            return default;
        }

        evidence.AppendLine($"  Feed: {KevCatalogService.FeedUrl}");
        evidence.AppendLine($"  Cache: {load.CachePath}{(load.CacheAgeHours is double age ? $" ({KevCatalogService.FormatHours(age)} hours old)" : " (none)")}");
        evidence.AppendLine($"  Source: {load.Source}");
        if (load.Detail is not null)
            evidence.AppendLine($"  Note: {load.Detail}");

        sb.AppendLine();
        sb.AppendLine("CISA KEV cross-reference:");
        if (load.SkipReason == KevCatalogService.OfflineMode)
        {
            sb.AppendLine(load.Catalog is null
                ? $"  Skipped: {KevCatalogService.OfflineMode}. There's no local KEV cache to fall back on."
                : $"  Skipped: {KevCatalogService.OfflineMode}. The feed wasn't downloaded; using the local cache ({KevCatalogService.FormatHours(load.CacheAgeHours ?? 0)} hours old).");
        }
        if (load.Catalog is null)
        {
            if (load.SkipReason != KevCatalogService.OfflineMode)
                sb.AppendLine($"  KEV check skipped: the feed is unavailable and there's no local cache ({load.Detail ?? "no detail"}).");
            return default;
        }

        var entries = load.Catalog.Entries;
        if (load.Rejected)
        {
            sb.AppendLine($"  KEV catalog rejected: only {entries.Count} entries (expected {load.MinimumEntries}+, possible corrupt data)");
            return default;
        }

        sb.AppendLine($"  KEV catalog: {entries.Count} known exploited vulnerabilities (source: {load.Source})");
        if (!string.IsNullOrEmpty(load.Catalog.CatalogVersion))
            sb.AppendLine($"  Catalog version: {load.Catalog.CatalogVersion}");

        var products = KevMatcher.ResolveProducts(snapshot.Products ?? new KevProductInventory(), snapshot.UpdateHistory);
        var dateNotes = new List<string> { $"{KevMatcher.Windows} {(latestOsDate is DateTime os ? FormatDate(os) : "unknown")}" };
        foreach (var family in products.Families.Where(f => f is not KevMatcher.Windows and not KevMatcher.Iis))
            dateNotes.Add($"{family} {(products.UpdateDates.TryGetValue(family, out var d) && d is DateTime date ? FormatDate(date) : "unknown")}");
        sb.AppendLine($"  Detected products: {string.Join(", ", products.Families)}");
        sb.AppendLine($"  Newest update per product: {string.Join(", ", dateNotes)}. KEV entries added before that are treated as fixed.");

        var hits = KevMatcher.Hits(entries, products.Families, products.UpdateDates, latestOsDate, today.ToDateTime(TimeOnly.MinValue));
        var overdue = hits.Count(h => h.Overdue);
        var ransomware = hits.Where(h => h.Ransomware).ToList();
        var ransomwareOverdue = ransomware.Count(h => h.Overdue);
        sb.AppendLine($"  {RansomwareReadinessEngine.FormatKevExposure(ransomware.Count, ransomwareOverdue)}");

        if (hits.Count == 0)
        {
            sb.AppendLine("  No KEV entries newer than this host's updates for detected products [OK]");
            return default;
        }

        sb.AppendLine($"  KEV entries newer than this host's updates: {hits.Count} (overdue: {overdue}, ransomware-linked: {ransomware.Count})");
        if (ransomwareOverdue > 0)
            sb.AppendLine($"FAIL: {ransomwareOverdue} ransomware-linked KEV {(ransomwareOverdue == 1 ? "entry is" : "entries are")} past the CISA due date.");
        else if (ransomware.Count > 0)
            sb.AppendLine($"WARNING: {ransomware.Count} ransomware-linked KEV {(ransomware.Count == 1 ? "entry isn't" : "entries aren't")} due yet. EP04 fails once one is overdue.");
        else
            sb.AppendLine($"WARNING: {hits.Count} KEV {(hits.Count == 1 ? "entry is" : "entries are")} newer than this host's updates for that product.");

        sb.AppendLine("  KEV entries to act on:");
        foreach (var hit in hits)
        {
            var tags = $"{(hit.Overdue ? " [OVERDUE]" : "")}{(hit.Ransomware ? " [RANSOMWARE]" : "")}{(hit.Unverified ? $" [no {hit.Family} update date to compare]" : "")}";
            sb.AppendLine($"    {hit.CveId} | {hit.Product} | {hit.Name} | Added: {(hit.DateAdded is DateTime added ? FormatDate(added) : "?")} | Due: {FormatDate(hit.DueDate)}{tags}");
        }

        return new KevOutcome(hits.Count, ransomwareOverdue);
    }

    /// <summary>
    /// True for monthly OS updates, including hotpatches: titles that carry this OS build
    /// ("2026-09 Security Update (KB5129195) (26200.9457)") or name a cumulative update, rollup or
    /// hotpatch. .NET, Defender definitions and the malicious software removal tool don't count.
    /// </summary>
    internal static bool IsOsQualityUpdate(string title, int osBuild)
    {
        if (string.IsNullOrWhiteSpace(title)) return false;
        if (Regex.IsMatch(title, @"\.NET|Security Intelligence|Defender|Definition|Malicious Software", RegexOptions.IgnoreCase))
            return false;
        if (osBuild > 0 && title.Contains($"({osBuild.ToString(CultureInfo.InvariantCulture)}.", StringComparison.Ordinal))
            return true;
        return Regex.IsMatch(title, @"Hotpatch|Cumulative Update for (Windows|Microsoft server operating system)|Monthly Quality Rollup", RegexOptions.IgnoreCase);
    }

    private static PatchSnapshot CollectSnapshot(EnvironmentInfo env, CancellationToken ct)
    {
        var (hotfixes, hotfixError) = QueryHotfixes(ct);
        ct.ThrowIfCancellationRequested();
        var (history, historyError) = UpdateHistoryReader.ReadInstalls(ct);
        return new PatchSnapshot
        {
            Hotfixes = hotfixes,
            HotfixError = hotfixError,
            UpdateHistory = history,
            UpdateHistoryError = historyError,
            OsCaption = env.OSCaption,
            OsBuild = env.OSBuild,
            OsVersion = env.OSVersion,
            Products = new KevProductInventoryReader().Read(),
        };
    }

    private static (List<HotfixInfo> Hotfixes, string? Error) QueryHotfixes(CancellationToken ct)
    {
        var results = new List<HotfixInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT HotFixID, InstalledOn, Description, InstalledBy FROM Win32_QuickFixEngineering");

            using var collection = searcher.Get();
            foreach (ManagementObject obj in collection)
            {
                using (obj)
                {
                    ct.ThrowIfCancellationRequested();
                    results.Add(new HotfixInfo(
                        obj["HotFixID"]?.ToString() ?? "Unknown",
                        ParseInstalledOn(obj["InstalledOn"]),
                        obj["Description"]?.ToString() ?? ""));
                }
            }
        }
        catch (ManagementException ex)
        {
            return (results, ex.Message.Trim());
        }

        return (results, null);
    }

    internal static DateTime ParseInstalledOn(object? raw)
    {
        if (raw is DateTime dt)
            return dt.Date;

        string value = raw?.ToString()?.Trim() ?? string.Empty;
        if (value.Length == 0)
            return DateTime.MinValue;

        string[] formats =
        [
            "M/d/yyyy",
            "MM/dd/yyyy",
            "M/d/yy",
            "MM/dd/yy",
            "yyyyMMdd",
            "yyyy-MM-dd"
        ];

        if (DateTime.TryParseExact(
            value,
            formats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces,
            out var exactParsed))
        {
            return exactParsed.Date;
        }

        if (DateTime.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces,
            out var invariantParsed))
        {
            return invariantParsed.Date;
        }

        return TryParseFileTime(value, out var fileTimeDate) ? fileTimeDate : DateTime.MinValue;
    }

    private static string FormatDate(DateTime value)
    {
        return value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    }

    private static bool TryParseFileTime(string value, out DateTime date)
    {
        string digits = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;

        NumberStyles style = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? NumberStyles.HexNumber
            : NumberStyles.Integer;

        if (long.TryParse(digits, style, CultureInfo.InvariantCulture, out long fileTime))
        {
            try
            {
                date = DateTime.FromFileTimeUtc(fileTime).ToLocalTime().Date;
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                date = DateTime.MinValue;
                return false;
            }
        }

        date = DateTime.MinValue;
        return false;
    }

    private static void CheckBuildCurrency(PatchSnapshot snapshot, DateOnly today, StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[OS Build Currency]");
        evidence.AppendLine($"  OS Build: {snapshot.OsBuild}");
        evidence.AppendLine($"  OS Version: {snapshot.OsVersion}");
        evidence.AppendLine($"  OS Caption: {snapshot.OsCaption}");
        evidence.AppendLine($"  Lifecycle table reviewed: {LifecycleVerdict.Format(LifecycleTable.Reviewed)}");

        if (snapshot.OsBuild <= 0)
        {
            sb.AppendLine("INFO: OS build number not available for currency check.");
            return;
        }

        var verdict = LifecycleTable.Evaluate(LifecycleTable.FindOs(snapshot.OsCaption, snapshot.OsBuild), today);
        evidence.AppendLine($"  Verdict: {verdict.State}");
        switch (verdict.State)
        {
            case LifecycleState.EndOfSupport:
                hasIssue = true;
                sb.AppendLine($"FAIL: OS build {snapshot.OsBuild} is {verdict.Describe(today)}. This release no longer gets security updates.");
                break;
            case LifecycleState.EsuEligible:
                sb.AppendLine($"INFO: OS build {snapshot.OsBuild} is {verdict.Describe(today)}. EP10 checks for an ESU license.");
                break;
            case LifecycleState.EndingSoon:
                sb.AppendLine($"WARNING: OS build {snapshot.OsBuild} is {verdict.Describe(today)}.");
                break;
            case LifecycleState.Supported:
                sb.AppendLine($"OS build {snapshot.OsBuild} is {verdict.Describe(today)}.");
                break;
            default:
                sb.AppendLine($"INFO: OS build {snapshot.OsBuild} isn't in the lifecycle table (reviewed {LifecycleVerdict.Format(LifecycleTable.Reviewed)}). Verify it is receiving security updates.");
                break;
        }
    }
}

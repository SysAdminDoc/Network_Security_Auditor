namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Globalization;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP04's CISA KEV matching, ported from the PowerShell EP04 helpers Get-Ep04KevFamily, Get-Ep04KevHits and
/// Get-Ep04NewestTitledDate. Both surfaces run the scenarios in Fixtures/Kev/ep04-kev-scenarios.json, so a
/// change here that the PowerShell check doesn't make (or the other way round) fails a test.
/// </summary>
internal static class KevMatcher
{
    internal const int MaxHits = 15;

    internal const string Windows = "Windows";
    internal const string Exchange = "Exchange";
    internal const string SqlServer = "SQL Server";
    internal const string Office = "Office";
    internal const string Edge = "Edge";
    internal const string DotNet = ".NET";
    internal const string Iis = "IIS";

    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // Checked in this order; the first match wins. "Internet Key Exchange" is a Windows component, not Exchange Server.
    private static readonly (Regex Pattern, string Family)[] FamilyRules =
    [
        (new Regex("Exchange Server", Options), Exchange),
        (new Regex("SQL Server", Options), SqlServer),
        (new Regex(@"^(Office|Word|Excel|PowerPoint|Outlook)\b|365 Apps", Options), Office),
        (new Regex(@"\bEdge\b", Options), Edge),
        (new Regex(@"\.NET", Options), DotNet),
        (new Regex("Internet Information Services", Options), Iis),
        (new Regex("Windows", Options), Windows),
    ];

    private static readonly Regex CveYear = new(@"^CVE-(\d{4})-", Options);

    // Update history titles that date a product: (title pattern, exclusions). Store app packages
    // ("9PLL735RFDSM-Microsoft.NET.Native.Runtime.2.2") and SQL Server client drivers don't patch the product.
    private static readonly Dictionary<string, (Regex Pattern, Regex? Exclude)> TitleRules = new(StringComparer.OrdinalIgnoreCase)
    {
        [Exchange] = (new Regex(@"Exchange Server 20\d\d", Options), null),
        [SqlServer] = (new Regex(@"SQL Server (19|20)\d\d", Options), new Regex("Driver|Native Client|Management Studio", Options)),
        [DotNet] = (new Regex(@"\.NET (Framework|\d+\.\d+)", Options), null),
        [Office] = (new Regex(@"Microsoft Office|Office 20\d\d|Microsoft (Word|Excel|Outlook|PowerPoint)", Options), null),
    };

    private static readonly Regex DefinitionTitle = new("Defender|Security Intelligence", Options);
    // Case-sensitive, like the PowerShell -cnotmatch: Store product IDs are 12 upper-case letters and digits.
    private static readonly Regex StorePackageTitle = new("^[0-9A-Z]{12}-", RegexOptions.CultureInvariant);

    internal sealed record KevHit(
        string CveId,
        string Product,
        string Name,
        string Family,
        DateTime? DateAdded,
        DateTime DueDate,
        bool Overdue,
        bool Ransomware,
        bool Unverified);

    /// <summary>Products on this host and the newest update date each one can show (null when unknown).</summary>
    internal sealed record ProductDates(IReadOnlyList<string> Families, IReadOnlyDictionary<string, DateTime?> UpdateDates);

    /// <summary>The update stream that fixes a Microsoft KEV entry's product, or null for a product EP04 doesn't look for.</summary>
    internal static string? FamilyOf(string? product)
    {
        if (string.IsNullOrEmpty(product))
            return null;
        foreach (var (pattern, family) in FamilyRules)
        {
            if (pattern.IsMatch(product))
                return family;
        }
        return null;
    }

    /// <summary>
    /// KEV entries that count against this host: due in the last year, for a product the host runs, and added to
    /// KEV after the newest update that would carry the fix (the OS update for Windows and IIS, the newer of that
    /// and the .NET update for .NET, the product's own update date for Office, Exchange, SQL Server and Edge).
    /// KEV often adds old CVEs years after the fix shipped, so an entry added before that update is treated as
    /// fixed. Microsoft updates are cumulative and a CVE ships its fix within about a year of its ID year, so an
    /// update dated after the end of the following year carries the fix too. With no update date to compare, the
    /// entry counts. A counted entry is overdue once its due date has passed. At most 15, latest due date first.
    /// </summary>
    internal static IReadOnlyList<KevHit> Hits(
        IEnumerable<KevEntry> entries,
        IEnumerable<string> families,
        IReadOnlyDictionary<string, DateTime?> updateDates,
        DateTime? latestOsDate,
        DateTime today)
    {
        var present = new HashSet<string>(families, StringComparer.OrdinalIgnoreCase);
        var hits = new List<KevHit>();
        foreach (var entry in entries)
        {
            if (entry is null || !string.Equals(entry.VendorProject, "Microsoft", StringComparison.OrdinalIgnoreCase))
                continue;
            var family = FamilyOf(entry.Product);
            if (family is null || !present.Contains(family))
                continue;

            var baseline = family switch
            {
                Windows or Iis => latestOsDate,
                DotNet => Newer(latestOsDate, DateFor(updateDates, DotNet)),
                _ => DateFor(updateDates, family),
            };

            if (entry.DueDate is not DateTime due || due <= today.AddDays(-365))
                continue;
            if (baseline is DateTime fixedBy && entry.DateAdded is DateTime added && added <= fixedBy)
                continue;
            if (baseline is DateTime updated && FixedByYear(entry.CveId, updated))
                continue;

            hits.Add(new KevHit(
                entry.CveId,
                entry.Product,
                entry.VulnerabilityName,
                family,
                entry.DateAdded,
                due,
                Overdue: due < today,
                Ransomware: string.Equals(entry.KnownRansomwareCampaignUse, "Known", StringComparison.OrdinalIgnoreCase),
                Unverified: baseline is null));
        }

        return hits.OrderByDescending(h => h.DueDate).Take(MaxHits).ToList();
    }

    /// <summary>True when the update is dated after the end of the year following the CVE's ID year.</summary>
    private static bool FixedByYear(string cveId, DateTime updated)
    {
        var match = CveYear.Match(cveId ?? "");
        if (!match.Success || !int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) || year >= 9998)
            return false;
        return new DateTime(year + 1, 12, 31) < updated;
    }

    /// <summary>Newest install date in the Windows Update history for one product, or null.</summary>
    internal static DateTime? NewestTitledDate(IEnumerable<EP04_PatchComplianceCheck.UpdateHistoryEntry>? history, string family)
    {
        if (history is null || !TitleRules.TryGetValue(family, out var rule))
            return null;
        DateTime? newest = null;
        foreach (var item in history)
        {
            var title = item?.Title ?? "";
            if (item is null
                || !rule.Pattern.IsMatch(title)
                || DefinitionTitle.IsMatch(title)
                || StorePackageTitle.IsMatch(title)
                || (rule.Exclude is not null && rule.Exclude.IsMatch(title)))
            {
                continue;
            }
            newest = Newer(newest, item.Date.Date);
        }
        return newest;
    }

    /// <summary>
    /// The PowerShell EP04 product detection: Windows always; Exchange and SQL Server by the newer of their
    /// service binary date and their update history titles (SQL titles only with a single instance, since titles
    /// don't say which instance they patched); IIS on the OS date; .NET by its update titles; Office by the newest
    /// of its update titles and its Click-to-Run app binaries; Edge by its binary date.
    /// </summary>
    internal static ProductDates ResolveProducts(KevProductInventory inventory, IReadOnlyList<EP04_PatchComplianceCheck.UpdateHistoryEntry>? history)
    {
        var families = new List<string> { Windows };
        var dates = new Dictionary<string, DateTime?>(StringComparer.OrdinalIgnoreCase);

        if (inventory.ExchangeInstalled)
        {
            families.Add(Exchange);
            dates[Exchange] = Newer(inventory.ExchangeServiceBinaryDate, NewestTitledDate(history, Exchange));
        }
        if (inventory.SqlInstanceCount > 0)
        {
            families.Add(SqlServer);
            var titled = inventory.SqlInstanceCount == 1 ? NewestTitledDate(history, SqlServer) : null;
            dates[SqlServer] = Newer(inventory.SqlOldestServiceBinaryDate, titled);
        }
        if (inventory.IisInstalled)
            families.Add(Iis);
        if (inventory.DotNetFrameworkInstalled)
        {
            families.Add(DotNet);
            dates[DotNet] = NewestTitledDate(history, DotNet);
        }
        if (inventory.OfficeInstalled)
        {
            families.Add(Office);
            DateTime? office = NewestTitledDate(history, Office);
            foreach (var binary in inventory.OfficeClickToRunBinaryDates)
                office = Newer(office, binary.Date);
            dates[Office] = office;
        }
        if (inventory.EdgeInstalled)
        {
            families.Add(Edge);
            if (inventory.EdgeBinaryDate is DateTime edge)
                dates[Edge] = edge.Date;
        }

        return new ProductDates(families, dates);
    }

    private static DateTime? DateFor(IReadOnlyDictionary<string, DateTime?> dates, string family) =>
        dates.TryGetValue(family, out var date) ? date : null;

    internal static DateTime? Newer(DateTime? a, DateTime? b) =>
        a is null ? b : b is null ? a : (a.Value >= b.Value ? a : b);
}

namespace NetworkSecurityAuditor.Data;

using System.Text.RegularExpressions;

internal enum LifecycleEdition { Any, HomePro, EnterpriseEducation, Ltsc, IotLtsc }

/// <summary>
/// One product release. <see cref="EndOfSupport"/> and <see cref="EsuEnd"/> are the last day updates
/// are published (Microsoft's pages print them as 6:59:59 AM PT on the following day).
/// </summary>
internal sealed record LifecycleEntry(
    string Key,
    string Product,
    string Match,
    int? Build,
    LifecycleEdition Edition,
    DateOnly EndOfSupport,
    DateOnly? EsuEnd = null);

internal enum LifecycleState { Supported, EndingSoon, EsuCovered, EsuEligible, EndOfSupport, Unknown }

internal enum EsuEnrollment { NotApplicable, Enrolled, NotEnrolled, Unknown }

internal sealed record LifecycleVerdict(LifecycleState State, LifecycleEntry? Entry, DateOnly? CoveredUntil, int DaysRemaining)
{
    public string Describe(DateOnly today) => State switch
    {
        LifecycleState.Supported => $"{Entry!.Product}: supported until {Format(Entry.EndOfSupport)} ({DaysRemaining} days)",
        LifecycleState.EndingSoon => $"{Entry!.Product}: support ends {Format(Entry.EndOfSupport)} ({DaysRemaining} days)",
        LifecycleState.EsuCovered => $"{Entry!.Product}: past end of support ({Format(Entry.EndOfSupport)}), covered by Extended Security Updates until {Format(CoveredUntil!.Value)}",
        LifecycleState.EsuEligible => $"{Entry!.Product}: past end of support ({Format(Entry.EndOfSupport)}); Extended Security Updates run until {Format(Entry.EsuEnd!.Value)} for enrolled systems, and enrollment can't be confirmed here",
        LifecycleState.EndOfSupport => $"{Entry!.Product}: end of support {Format(Entry.EndOfSupport)}{(Entry.EsuEnd is { } esu && esu >= today ? $", not enrolled in Extended Security Updates (available until {Format(esu)})" : Entry.EsuEnd is { } ended ? $", Extended Security Updates ended {Format(ended)}" : string.Empty)}",
        _ => "not in the lifecycle table",
    };

    internal static string Format(DateOnly d) => d.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>
/// Dated Microsoft lifecycle table shared by EP04 and EP10. The PowerShell EP10 block carries the
/// same entries (keys and dates), and LifecycleTableTests fails if the two drift apart.
/// </summary>
internal static class LifecycleTable
{
    public const string Source = "https://learn.microsoft.com/en-us/lifecycle/products/";
    public static readonly DateOnly Reviewed = new(2026, 9, 30);
    /// <summary>Support ending within this many days is reported as ending soon.</summary>
    public const int EndingSoonDays = 180;

    private static DateOnly D(int y, int m, int d) => new(y, m, d);

    // Order matters: the first match wins, so specific entries come before general ones.
    public static readonly IReadOnlyList<LifecycleEntry> Entries =
    [
        new("win11-25h2-homepro", "Windows 11 25H2 (Home/Pro)", "Windows 11", 26200, LifecycleEdition.HomePro, D(2027, 10, 12)),
        new("win11-25h2-ent", "Windows 11 25H2 (Enterprise/Education)", "Windows 11", 26200, LifecycleEdition.EnterpriseEducation, D(2028, 10, 10)),
        new("win11-ltsc2024-iot", "Windows 11 IoT Enterprise LTSC 2024", "Windows 11", 26100, LifecycleEdition.IotLtsc, D(2034, 10, 10)),
        new("win11-ltsc2024", "Windows 11 Enterprise LTSC 2024", "Windows 11", 26100, LifecycleEdition.Ltsc, D(2029, 10, 9)),
        new("win11-24h2-homepro", "Windows 11 24H2 (Home/Pro)", "Windows 11", 26100, LifecycleEdition.HomePro, D(2026, 10, 13)),
        new("win11-24h2-ent", "Windows 11 24H2 (Enterprise/Education)", "Windows 11", 26100, LifecycleEdition.EnterpriseEducation, D(2027, 10, 12)),
        new("win11-23h2-homepro", "Windows 11 23H2 (Home/Pro)", "Windows 11", 22631, LifecycleEdition.HomePro, D(2025, 11, 11)),
        new("win11-23h2-ent", "Windows 11 23H2 (Enterprise/Education)", "Windows 11", 22631, LifecycleEdition.EnterpriseEducation, D(2026, 11, 10)),
        new("win11-22h2-homepro", "Windows 11 22H2 (Home/Pro)", "Windows 11", 22621, LifecycleEdition.HomePro, D(2024, 10, 8)),
        new("win11-22h2-ent", "Windows 11 22H2 (Enterprise/Education)", "Windows 11", 22621, LifecycleEdition.EnterpriseEducation, D(2025, 10, 14)),
        new("win11-21h2-homepro", "Windows 11 21H2 (Home/Pro)", "Windows 11", 22000, LifecycleEdition.HomePro, D(2023, 10, 10)),
        new("win11-21h2-ent", "Windows 11 21H2 (Enterprise/Education)", "Windows 11", 22000, LifecycleEdition.EnterpriseEducation, D(2024, 10, 8)),
        new("win10-ltsc2021-iot", "Windows 10 IoT Enterprise LTSC 2021", "Windows 10", 19044, LifecycleEdition.IotLtsc, D(2032, 1, 13)),
        new("win10-ltsc2021", "Windows 10 Enterprise LTSC 2021", "Windows 10", 19044, LifecycleEdition.Ltsc, D(2027, 1, 12)),
        new("win10-ltsc2019", "Windows 10 Enterprise LTSC 2019", "Windows 10", 17763, LifecycleEdition.Ltsc, D(2029, 1, 9)),
        new("win10-ltsc2019-iot", "Windows 10 IoT Enterprise LTSC 2019", "Windows 10", 17763, LifecycleEdition.IotLtsc, D(2029, 1, 9)),
        new("win10-ltsb2016", "Windows 10 Enterprise LTSB 2016", "Windows 10", 14393, LifecycleEdition.Ltsc, D(2026, 10, 13)),
        new("win10-ltsb2016-iot", "Windows 10 IoT Enterprise LTSB 2016", "Windows 10", 14393, LifecycleEdition.IotLtsc, D(2026, 10, 13)),
        new("win10-ltsb2015", "Windows 10 Enterprise LTSB 2015", "Windows 10", 10240, LifecycleEdition.Ltsc, D(2025, 10, 14)),
        new("win10-ltsb2015-iot", "Windows 10 IoT Enterprise LTSB 2015", "Windows 10", 10240, LifecycleEdition.IotLtsc, D(2025, 10, 14)),
        new("win10-22h2", "Windows 10 22H2", "Windows 10", 19045, LifecycleEdition.Any, D(2025, 10, 14), D(2028, 10, 10)),
        new("win10-older", "Windows 10 (older than 22H2)", "Windows 10", null, LifecycleEdition.Any, D(2024, 6, 11)),
        new("win81", "Windows 8.1", "Windows 8.1", null, LifecycleEdition.Any, D(2023, 1, 10)),
        new("win8", "Windows 8", "Windows 8", null, LifecycleEdition.Any, D(2016, 1, 12)),
        new("win7", "Windows 7", "Windows 7", null, LifecycleEdition.Any, D(2020, 1, 14), D(2023, 1, 10)),
        new("winvista", "Windows Vista", "Windows Vista", null, LifecycleEdition.Any, D(2017, 4, 11)),
        new("winxp", "Windows XP", "Windows XP", null, LifecycleEdition.Any, D(2014, 4, 8)),
        new("server2025", "Windows Server 2025", "Server 2025", null, LifecycleEdition.Any, D(2034, 11, 14)),
        new("server2022", "Windows Server 2022", "Server 2022", null, LifecycleEdition.Any, D(2031, 10, 14)),
        new("server2019", "Windows Server 2019", "Server 2019", null, LifecycleEdition.Any, D(2029, 1, 9)),
        new("server2016", "Windows Server 2016", "Server 2016", null, LifecycleEdition.Any, D(2027, 1, 12)),
        new("server2012r2", "Windows Server 2012 R2", "Server 2012 R2", null, LifecycleEdition.Any, D(2023, 10, 10), D(2026, 10, 13)),
        new("server2012", "Windows Server 2012", "Server 2012", null, LifecycleEdition.Any, D(2023, 10, 10), D(2026, 10, 13)),
        new("server2008r2", "Windows Server 2008 R2", "Server 2008 R2", null, LifecycleEdition.Any, D(2020, 1, 14), D(2023, 1, 10)),
        new("server2008", "Windows Server 2008", "Server 2008", null, LifecycleEdition.Any, D(2020, 1, 14), D(2023, 1, 10)),
        new("server2003", "Windows Server 2003", "Server 2003", null, LifecycleEdition.Any, D(2015, 7, 14)),
        new("sql2019", "SQL Server 2019", "SQL Server 2019", null, LifecycleEdition.Any, D(2030, 1, 8)),
        new("sql2017", "SQL Server 2017", "SQL Server 2017", null, LifecycleEdition.Any, D(2027, 10, 12)),
        new("sql2016", "SQL Server 2016", "SQL Server 2016", null, LifecycleEdition.Any, D(2026, 7, 14), D(2029, 7, 16)),
        new("sql2014", "SQL Server 2014", "SQL Server 2014", null, LifecycleEdition.Any, D(2024, 7, 9), D(2027, 7, 12)),
        new("sql2012-older", "SQL Server 2012 or older", "SQL Server 2012 or older", null, LifecycleEdition.Any, D(2022, 7, 12)),
        new("office2019", "Office 2019", "Office 2019", null, LifecycleEdition.Any, D(2025, 10, 14)),
        new("office2016", "Office 2016", "Office 2016", null, LifecycleEdition.Any, D(2025, 10, 14)),
        new("exchange2019", "Exchange Server 2019", "Exchange Server 2019", null, LifecycleEdition.Any, D(2025, 10, 14)),
        new("exchange2016", "Exchange Server 2016", "Exchange Server 2016", null, LifecycleEdition.Any, D(2025, 10, 14)),
    ];

    /// <summary>
    /// Windows 10 ESU add-on licenses (activation IDs from Microsoft's "Enable Extended Security Updates"
    /// page) and the last day each year's license covers.
    /// </summary>
    public static readonly IReadOnlyList<(int Year, Guid ActivationId, DateOnly CoversUntil)> Windows10EsuYears =
    [
        (1, new Guid("f520e45e-7413-4a34-a497-d2765967d094"), D(2026, 10, 13)),
        (2, new Guid("1043add5-23b1-4afb-9a0f-64343c8f3f8d"), D(2027, 10, 12)),
        (3, new Guid("83d49986-add3-41d7-ba33-87c7bfb5c0fb"), D(2028, 10, 10)),
    ];

    /// <summary>Finds the entry for an OS caption or AD operatingSystem value and its build number.</summary>
    public static LifecycleEntry? FindOs(string? caption, int build)
    {
        if (string.IsNullOrWhiteSpace(caption))
            return null;
        var edition = LifecycleEditionClassifier.Classify(caption);
        var isLtsc = edition is LifecycleEdition.Ltsc or LifecycleEdition.IotLtsc;
        foreach (var entry in Entries)
        {
            if (!caption.Contains(entry.Match, StringComparison.OrdinalIgnoreCase)) continue;
            if (entry.Build is { } b && b != build) continue;
            if (entry.Edition != LifecycleEdition.Any && entry.Edition != edition) continue;
            // LTSB/LTSC share build numbers with general-availability Windows 10/11 releases but have their own dates.
            if (isLtsc && entry.Edition == LifecycleEdition.Any && entry.Match.StartsWith("Windows 1", StringComparison.Ordinal)) continue;
            return entry;
        }
        return null;
    }

    public static LifecycleEntry? FindProduct(string product) =>
        Entries.FirstOrDefault(e => e.Match.Equals(product, StringComparison.OrdinalIgnoreCase));

    /// <summary>Reads the build number from an AD operatingSystemVersion value such as "10.0 (19045)".</summary>
    public static int ParseAdBuild(string? operatingSystemVersion)
    {
        if (string.IsNullOrWhiteSpace(operatingSystemVersion)) return 0;
        var m = Regex.Match(operatingSystemVersion, @"\((\d+)\)");
        return m.Success && int.TryParse(m.Groups[1].Value, out var build) ? build : 0;
    }

    public static LifecycleVerdict Evaluate(LifecycleEntry? entry, DateOnly today, EsuEnrollment esu = EsuEnrollment.Unknown, DateOnly? esuCoversUntil = null)
    {
        if (entry is null)
            return new LifecycleVerdict(LifecycleState.Unknown, null, null, 0);

        var days = entry.EndOfSupport.DayNumber - today.DayNumber;
        if (days >= 0)
            return new LifecycleVerdict(days <= EndingSoonDays ? LifecycleState.EndingSoon : LifecycleState.Supported, entry, null, days);

        if (entry.EsuEnd is { } esuEnd && today <= esuEnd)
        {
            if (esu == EsuEnrollment.Enrolled && esuCoversUntil is { } until && today <= until)
                return new LifecycleVerdict(LifecycleState.EsuCovered, entry, until < esuEnd ? until : esuEnd, days);
            if (esu == EsuEnrollment.Unknown)
                return new LifecycleVerdict(LifecycleState.EsuEligible, entry, null, days);
        }
        return new LifecycleVerdict(LifecycleState.EndOfSupport, entry, null, days);
    }
}

internal static class LifecycleEditionClassifier
{
    /// <summary>
    /// Maps a caption to its servicing channel. Pro Education follows the Home/Pro timeline; LTSB/LTSC
    /// and their IoT variants have their own dates.
    /// </summary>
    public static LifecycleEdition Classify(string caption)
    {
        var ltsc = caption.Contains("LTSC", StringComparison.OrdinalIgnoreCase) || caption.Contains("LTSB", StringComparison.OrdinalIgnoreCase);
        if (ltsc)
            return caption.Contains("IoT", StringComparison.OrdinalIgnoreCase) ? LifecycleEdition.IotLtsc : LifecycleEdition.Ltsc;
        if (caption.Contains("Pro Education", StringComparison.OrdinalIgnoreCase))
            return LifecycleEdition.HomePro;
        if (caption.Contains("Enterprise", StringComparison.OrdinalIgnoreCase) || caption.Contains("Education", StringComparison.OrdinalIgnoreCase))
            return LifecycleEdition.EnterpriseEducation;
        return LifecycleEdition.HomePro;
    }
}

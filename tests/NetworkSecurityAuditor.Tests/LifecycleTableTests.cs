using System.Globalization;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;

namespace NetworkSecurityAuditor.Tests;

public class LifecycleTableTests
{
    private static readonly DateOnly Today = new(2026, 9, 30);

    [Theory]
    [InlineData("Microsoft Windows 11 Pro", 26200, "win11-25h2-homepro")]
    [InlineData("Microsoft Windows 11 Enterprise", 26100, "win11-24h2-ent")]
    [InlineData("Microsoft Windows 11 Pro Education", 22631, "win11-23h2-homepro")]
    [InlineData("Microsoft Windows 11 Education", 22631, "win11-23h2-ent")]
    [InlineData("Microsoft Windows 11 Enterprise LTSC", 26100, "win11-ltsc2024")]
    [InlineData("Microsoft Windows 11 IoT Enterprise LTSC", 26100, "win11-ltsc2024-iot")]
    [InlineData("Microsoft Windows 10 Pro", 19045, "win10-22h2")]
    [InlineData("Windows 10 Enterprise", 19044, "win10-older")]
    [InlineData("Microsoft Windows 10 Enterprise LTSC", 19044, "win10-ltsc2021")]
    [InlineData("Microsoft Windows 10 IoT Enterprise LTSC", 19044, "win10-ltsc2021-iot")]
    [InlineData("Microsoft Windows 10 Enterprise 2016 LTSB", 14393, "win10-ltsb2016")]
    [InlineData("Microsoft Windows Server 2012 R2 Standard", 9600, "server2012r2")]
    [InlineData("Windows Server 2012 Datacenter", 9200, "server2012")]
    [InlineData("Windows Server 2025 Datacenter", 26100, "server2025")]
    [InlineData("Microsoft Windows 8.1 Pro", 9600, "win81")]
    [InlineData("Windows 7 Professional", 7601, "win7")]
    public void Finds_The_Release_For_A_Caption_And_Build(string caption, int build, string expectedKey)
    {
        Assert.Equal(expectedKey, LifecycleTable.FindOs(caption, build)?.Key);
    }

    [Theory]
    [InlineData("Microsoft Windows 11 Pro", 28000)]
    [InlineData("Microsoft Windows 10 Enterprise LTSC", 20348)]
    [InlineData("Windows Server Datacenter", 20348)]
    [InlineData("", 26100)]
    public void Unknown_Releases_Return_No_Entry(string caption, int build)
    {
        Assert.Null(LifecycleTable.FindOs(caption, build));
    }

    [Fact]
    public void Evaluation_Uses_The_Given_Date()
    {
        var pro24h2 = LifecycleTable.FindOs("Windows 11 Pro", 26100);
        var ending = LifecycleTable.Evaluate(pro24h2, Today);
        Assert.Equal(LifecycleState.EndingSoon, ending.State);
        Assert.Equal(13, ending.DaysRemaining);

        Assert.Equal(LifecycleState.Supported, LifecycleTable.Evaluate(LifecycleTable.FindOs("Windows 11 Pro", 26200), Today).State);
        Assert.Equal(LifecycleState.EndOfSupport, LifecycleTable.Evaluate(pro24h2, new DateOnly(2026, 10, 14)).State);
        Assert.Equal(LifecycleState.Unknown, LifecycleTable.Evaluate(null, Today).State);
    }

    [Fact]
    public void Windows10_Esu_Enrollment_Decides_Between_Covered_Eligible_And_Ended()
    {
        var win10 = LifecycleTable.FindOs("Windows 10 Pro", 19045);

        var covered = LifecycleTable.Evaluate(win10, Today, EsuEnrollment.Enrolled, new DateOnly(2026, 10, 13));
        Assert.Equal(LifecycleState.EsuCovered, covered.State);
        Assert.Equal(new DateOnly(2026, 10, 13), covered.CoveredUntil);
        Assert.Contains("covered by Extended Security Updates until 2026-10-13", covered.Describe(Today));

        Assert.Equal(LifecycleState.EndOfSupport, LifecycleTable.Evaluate(win10, Today, EsuEnrollment.NotEnrolled).State);
        Assert.Equal(LifecycleState.EsuEligible, LifecycleTable.Evaluate(win10, Today, EsuEnrollment.Unknown).State);
        // A Year 1 license stops covering after its year even though ESU runs to 2028.
        Assert.Equal(LifecycleState.EndOfSupport,
            LifecycleTable.Evaluate(win10, new DateOnly(2026, 11, 1), EsuEnrollment.Enrolled, new DateOnly(2026, 10, 13)).State);
    }

    [Fact]
    public void Esu_Windows_Close_On_Their_Own_Dates()
    {
        var r2 = LifecycleTable.FindOs("Windows Server 2012 R2 Standard", 9600);
        Assert.Equal(LifecycleState.EsuEligible, LifecycleTable.Evaluate(r2, new DateOnly(2026, 10, 13)).State);
        Assert.Equal(LifecycleState.EndOfSupport, LifecycleTable.Evaluate(r2, new DateOnly(2026, 10, 14)).State);

        var sql2016 = LifecycleTable.FindProduct("SQL Server 2016");
        Assert.Equal(LifecycleState.EsuEligible, LifecycleTable.Evaluate(sql2016, Today).State);
        Assert.Equal(LifecycleState.Supported, LifecycleTable.Evaluate(sql2016, new DateOnly(2025, 12, 1)).State);
    }

    [Theory]
    [InlineData("10.0 (19045)", 19045)]
    [InlineData("10.0 (26100)", 26100)]
    [InlineData("6.3 (9600)", 9600)]
    [InlineData("", 0)]
    [InlineData(null, 0)]
    public void Parses_Ad_Build_Numbers(string? value, int expected)
    {
        Assert.Equal(expected, LifecycleTable.ParseAdBuild(value));
    }

    [Fact]
    public void Table_Is_Well_Formed()
    {
        Assert.Equal(LifecycleTable.Entries.Count, LifecycleTable.Entries.Select(e => e.Key).Distinct().Count());
        Assert.All(LifecycleTable.Entries, e => Assert.True(e.EsuEnd is null || e.EsuEnd > e.EndOfSupport, e.Key));
        Assert.Equal([1, 2, 3], LifecycleTable.Windows10EsuYears.Select(y => y.Year));
        Assert.Equal(LifecycleTable.FindOs("Windows 10 Pro", 19045)!.EsuEnd, LifecycleTable.Windows10EsuYears[^1].CoversUntil);
    }

    // The PowerShell EP10 block carries its own copy of the table; this keeps the two in step.
    [Fact]
    public void PowerShell_Table_Matches_The_App_Table()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "NetworkSecurityAudit.ps1"));
        var rows = Regex.Matches(script,
            @"@\{ Key='(?<key>[^']+)'; Product='(?<product>[^']+)'; Match='(?<match>[^']+)'; Build=(?<build>\d+|\$null); Edition='(?<edition>\w+)'; EOS='(?<eos>[\d-]+)'; ESU='(?<esu>[\d-]*)' \}");

        Assert.Equal(LifecycleTable.Entries.Count, rows.Count);
        for (var i = 0; i < rows.Count; i++)
        {
            var row = rows[i].Groups;
            var entry = LifecycleTable.Entries[i];
            Assert.Equal(entry.Key, row["key"].Value);
            Assert.Equal(entry.Product, row["product"].Value);
            Assert.Equal(entry.Match, row["match"].Value);
            Assert.Equal(entry.Build?.ToString(CultureInfo.InvariantCulture) ?? "$null", row["build"].Value);
            Assert.Equal(entry.Edition.ToString(), row["edition"].Value);
            Assert.Equal(LifecycleVerdict.Format(entry.EndOfSupport), row["eos"].Value);
            Assert.Equal(entry.EsuEnd is { } esu ? LifecycleVerdict.Format(esu) : "", row["esu"].Value);
        }

        var esuRows = Regex.Matches(script, @"@\{ Year=(?<year>\d); Id='(?<id>[0-9a-f-]+)'; Until='(?<until>[\d-]+)' \}");
        Assert.Equal(LifecycleTable.Windows10EsuYears.Count, esuRows.Count);
        for (var i = 0; i < esuRows.Count; i++)
        {
            var (year, id, until) = LifecycleTable.Windows10EsuYears[i];
            Assert.Equal(year.ToString(CultureInfo.InvariantCulture), esuRows[i].Groups["year"].Value);
            Assert.Equal(id, Guid.Parse(esuRows[i].Groups["id"].Value));
            Assert.Equal(LifecycleVerdict.Format(until), esuRows[i].Groups["until"].Value);
        }

        Assert.Contains($"$lifecycleReviewed = '{LifecycleVerdict.Format(LifecycleTable.Reviewed)}'", script);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

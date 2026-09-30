namespace NetworkSecurityAuditor.Tests;

using System.Globalization;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;

public sealed class EP04PatchComplianceTests
{
    [Fact]
    public void ParseInstalledOn_Uses_Invariant_Culture_For_US_Wmi_Dates()
    {
        CultureInfo originalCulture = CultureInfo.CurrentCulture;
        CultureInfo originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("fr-FR");

            var parsed = EP04_PatchComplianceCheck.ParseInstalledOn("1/31/2026");

            Assert.Equal(new DateTime(2026, 1, 31), parsed);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public void ParseInstalledOn_Handles_Hex_FileTime_Values()
    {
        var expected = new DateTime(2026, 1, 31, 0, 0, 0, DateTimeKind.Utc);
        string raw = "0x" + expected.ToFileTimeUtc().ToString("x", CultureInfo.InvariantCulture);

        var parsed = EP04_PatchComplianceCheck.ParseInstalledOn(raw);

        Assert.Equal(expected.ToLocalTime().Date, parsed);
    }

    [Fact]
    public void ParseInstalledOn_Handles_Compact_Wmi_Date_Values()
    {
        var parsed = EP04_PatchComplianceCheck.ParseInstalledOn("20260131");

        Assert.Equal(new DateTime(2026, 1, 31), parsed);
    }

    private static readonly DateOnly Today = new(2026, 9, 30);

    private static EP04_PatchComplianceCheck.PatchSnapshot Snapshot(DateTime lastHotfix, params (string Title, DateTime Date)[] history) => new()
    {
        Hotfixes = [new EP04_PatchComplianceCheck.HotfixInfo("KB5051987", lastHotfix, "Security Update")],
        UpdateHistory = history.Select(h => new EP04_PatchComplianceCheck.UpdateHistoryEntry(h.Title, h.Date)).ToList(),
        OsCaption = "Microsoft Windows 11 Enterprise",
        OsBuild = 26100,
        OsVersion = "26100.4061",
    };

    [Fact]
    public void Hotpatch_Month_After_An_Older_Baseline_Is_Not_Stale()
    {
        // The baseline is 70 days old in the hotfix list; the hotpatch 12 days ago only shows in the WU history.
        var assessment = EP04_PatchComplianceCheck.Assess(
            Snapshot(new DateTime(2026, 7, 22), ("2026-09 Hotpatch for Windows 11 Version 24H2 (KB5130001) (26100.4061)", new DateTime(2026, 9, 18))),
            Today);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("(Windows Update history), 2026-09-18 (12d ago)", assessment.Findings);
    }

    [Fact]
    public void Stale_In_Both_Sources_Fails()
    {
        var assessment = EP04_PatchComplianceCheck.Assess(
            Snapshot(new DateTime(2026, 6, 10), ("2026-09 .NET Framework Security Update (KB5126052)", new DateTime(2026, 9, 20))),
            Today);

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("Last OS update is 112 days old", assessment.Findings);
    }

    [Theory]
    [InlineData("2026-09 Security Update (KB5129195) (26200.9457)", 26200, true)]
    [InlineData("2026-09 Security Update (KB5129195) (26200.9457)", 26100, false)]
    [InlineData("2026-05 Hotpatch for Windows Server 2025 (KB5058497)", 26100, true)]
    [InlineData("2024-01 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5034123)", 22631, true)]
    [InlineData("2026-09 .NET Framework Security Update (KB5126052)", 26200, false)]
    [InlineData("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.437.1)", 26200, false)]
    [InlineData("9NMPJ99VJBWV-Microsoft.YourPhone", 26200, false)]
    public void Recognizes_Os_Quality_Updates(string title, int build, bool expected)
    {
        Assert.Equal(expected, EP04_PatchComplianceCheck.IsOsQualityUpdate(title, build));
    }

    [Fact]
    public void Build_Currency_Comes_From_The_Lifecycle_Table()
    {
        var current = EP04_PatchComplianceCheck.Assess(Snapshot(new DateTime(2026, 9, 22)) with { OsCaption = "Microsoft Windows 11 Pro", OsBuild = 26200 }, Today);
        var ended = EP04_PatchComplianceCheck.Assess(Snapshot(new DateTime(2026, 9, 22)) with { OsCaption = "Microsoft Windows 11 Pro", OsBuild = 22621 }, Today);
        var win10 = EP04_PatchComplianceCheck.Assess(Snapshot(new DateTime(2026, 9, 22)) with { OsCaption = "Microsoft Windows 10 Pro", OsBuild = 19045 }, Today);

        Assert.Equal(CheckStatus.Pass, current.Status);
        Assert.Contains("Windows 11 25H2 (Home/Pro): supported until 2027-10-12", current.Findings);
        Assert.Equal(CheckStatus.Fail, ended.Status);
        Assert.Contains("Windows 11 22H2 (Home/Pro): end of support 2024-10-08", ended.Findings);
        // Patch recency covers an ESU-enrolled Windows 10 host; EP10 judges the enrollment.
        Assert.Equal(CheckStatus.Pass, win10.Status);
        Assert.Contains("EP10 checks for an ESU license", win10.Findings);
    }

    [Fact]
    public void Windows_Update_History_Dates_Are_Read_As_Utc()
    {
        var unspecified = new DateTime(2026, 9, 22, 3, 30, 0, DateTimeKind.Unspecified);
        var expected = new DateTime(2026, 9, 22, 3, 30, 0, DateTimeKind.Utc).ToLocalTime();

        Assert.Equal(expected, UpdateHistoryReader.ToLocal(unspecified));
        Assert.Equal(expected, UpdateHistoryReader.ToLocal(DateTime.SpecifyKind(unspecified, DateTimeKind.Utc)));
        Assert.Equal(expected, UpdateHistoryReader.ToLocal(expected));
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var env = NetworkSecurityAuditor.Services.EnvironmentDetector.Detect();
        var cacheDir = Path.Combine(Path.GetTempPath(), "nsa-kev-tests", Guid.NewGuid().ToString("N"));
        try
        {
            // The host collection is live; the KEV feed comes from the recorded fixture, so the test makes no network call.
            var kev = new NetworkSecurityAuditor.Services.KevCatalogService(_ => Task.FromResult(KevFixtures.FeedText), cacheDir, null, minimumEntries: 10);
            var result = await new EP04_PatchComplianceCheck(null, kev, null).ExecuteAsync(env, new AuditOptions(), CancellationToken.None);

            Assert.Null(result.Error);
            Assert.Contains("[Windows Update History (OS quality updates)]", result.Evidence);
            Assert.DoesNotContain("Couldn't read:", result.Evidence);
            Assert.Contains("KEV catalog: 12 known exploited vulnerabilities (source: live download)", result.Findings);
            Assert.Contains("  Detected products: Windows", result.Findings);
        }
        finally
        {
            try { Directory.Delete(cacheDir, recursive: true); } catch (DirectoryNotFoundException) { }
        }
    }
}

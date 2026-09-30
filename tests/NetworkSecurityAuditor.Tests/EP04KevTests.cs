namespace NetworkSecurityAuditor.Tests;

using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.ViewModels;

/// <summary>Recorded CISA KEV feed and the scenarios the PowerShell EP04 Pester tests also run.</summary>
internal static class KevFixtures
{
    public static string Folder { get; } = Path.Combine(FindRepoRoot(), "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Kev");

    public static string FeedText => File.ReadAllText(Path.Combine(Folder, Scenarios.GetProperty("feed").GetString()!));

    public static KevCatalog Catalog => KevCatalogService.Parse(FeedText);

    private static readonly Lazy<JsonDocument> s_scenarios = new(() => JsonDocument.Parse(File.ReadAllText(Path.Combine(Folder, "ep04-kev-scenarios.json"))));

    public static JsonElement Scenarios => s_scenarios.Value.RootElement;

    public static DateTime? Date(JsonElement value) => value.ValueKind == JsonValueKind.Null
        ? null
        : DateTime.Parse(value.GetString()!, CultureInfo.InvariantCulture).Date;

    public static DateTime Day(string value) => DateTime.ParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}

public sealed class EP04KevMatchingTests
{
    public static TheoryData<string> ScenarioNames()
    {
        var data = new TheoryData<string>();
        foreach (var scenario in KevFixtures.Scenarios.GetProperty("hitScenarios").EnumerateArray())
            data.Add(scenario.GetProperty("name").GetString()!);
        return data;
    }

    [Fact]
    public void Recorded_Feed_Parses_In_The_Cisa_Shape()
    {
        var catalog = KevFixtures.Catalog;

        Assert.Equal("2026.09.29", catalog.CatalogVersion);
        Assert.Equal(12, catalog.Entries.Count);
        var exchange = Assert.Single(catalog.Entries, e => e.CveId == "CVE-2023-21529");
        Assert.Equal("Exchange Server", exchange.Product);
        Assert.Equal(new DateTime(2026, 4, 13), exchange.DateAdded);
        Assert.Equal(new DateTime(2026, 4, 27), exchange.DueDate);
        Assert.Equal("Known", exchange.KnownRansomwareCampaignUse);
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public void Shared_Scenario_Gives_The_Same_Hits_As_The_PowerShell_Check(string name)
    {
        var scenario = KevFixtures.Scenarios.GetProperty("hitScenarios").EnumerateArray()
            .Single(s => s.GetProperty("name").GetString() == name);
        var dates = new Dictionary<string, DateTime?>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in scenario.GetProperty("updateDates").EnumerateObject())
            dates[p.Name] = KevFixtures.Date(p.Value);

        var hits = KevMatcher.Hits(
            KevFixtures.Catalog.Entries,
            scenario.GetProperty("families").EnumerateArray().Select(f => f.GetString()!).ToList(),
            dates,
            KevFixtures.Date(scenario.GetProperty("latestOsDate")),
            KevFixtures.Date(scenario.GetProperty("today"))!.Value);

        var expected = scenario.GetProperty("expected").EnumerateArray().ToList();
        Assert.Equal(expected.Select(e => e.GetProperty("cveID").GetString()), hits.Select(h => h.CveId));
        for (var i = 0; i < expected.Count; i++)
        {
            Assert.Equal(expected[i].GetProperty("family").GetString(), hits[i].Family);
            Assert.Equal(expected[i].GetProperty("overdue").GetBoolean(), hits[i].Overdue);
            Assert.Equal(expected[i].GetProperty("ransomware").GetBoolean(), hits[i].Ransomware);
            Assert.Equal(expected[i].GetProperty("unverified").GetBoolean(), hits[i].Unverified);
        }
    }

    [Fact]
    public void Shared_Product_Names_Map_To_The_Same_Update_Stream()
    {
        foreach (var c in KevFixtures.Scenarios.GetProperty("familyCases").EnumerateArray())
        {
            var product = c.GetProperty("product").GetString();
            var family = c.GetProperty("family");
            Assert.True(
                (family.ValueKind == JsonValueKind.Null ? null : family.GetString()) == KevMatcher.FamilyOf(product),
                $"{product} mapped to {KevMatcher.FamilyOf(product) ?? "nothing"}");
        }
    }

    [Fact]
    public void Shared_Update_Titles_Date_Only_The_Product_They_Name()
    {
        var titled = KevFixtures.Scenarios.GetProperty("titledDates");
        var history = titled.GetProperty("history").EnumerateArray()
            .Select(h => new EP04_PatchComplianceCheck.UpdateHistoryEntry(
                h.GetProperty("title").GetString()!,
                DateTime.Parse(h.GetProperty("date").GetString()!, CultureInfo.InvariantCulture)))
            .ToList();

        foreach (var p in titled.GetProperty("expected").EnumerateObject())
            Assert.True(KevFixtures.Date(p.Value) == KevMatcher.NewestTitledDate(history, p.Name), $"{p.Name}: {KevMatcher.NewestTitledDate(history, p.Name)}");
    }

    [Fact]
    public void More_Than_Fifteen_Hits_Keep_The_Latest_Due_Dates()
    {
        var entries = Enumerable.Range(1, 20)
            .Select(i => new KevEntry($"CVE-2026-{i:00000}", "Microsoft", "Windows", $"Entry {i}", new DateTime(2026, 9, 1), new DateTime(2026, 9, 1).AddDays(i), "Unknown"))
            .ToList();

        var hits = KevMatcher.Hits(entries, [KevMatcher.Windows], new Dictionary<string, DateTime?>(), null, new DateTime(2026, 9, 30));

        Assert.Equal(KevMatcher.MaxHits, hits.Count);
        Assert.Equal("CVE-2026-00020", hits[0].CveId);
        Assert.Equal("CVE-2026-00006", hits[^1].CveId);
    }
}

public sealed class EP04KevProductTests
{
    private static EP04_PatchComplianceCheck.UpdateHistoryEntry Update(string title, string date) =>
        new(title, KevFixtures.Day(date).AddHours(14));

    [Fact]
    public void Sql_Server_Titles_Count_Only_On_A_Single_Instance_Host()
    {
        var history = new[] { Update("Security Update for SQL Server 2019 RTM GDR (KB5046859)", "2026-07-15") };

        var single = KevMatcher.ResolveProducts(new KevProductInventory { SqlInstanceCount = 1, SqlOldestServiceBinaryDate = KevFixtures.Day("2019-09-24") }, history);
        var several = KevMatcher.ResolveProducts(new KevProductInventory { SqlInstanceCount = 2, SqlOldestServiceBinaryDate = KevFixtures.Day("2019-09-24") }, history);

        Assert.Equal(new[] { "Windows", "SQL Server" }, single.Families);
        Assert.Equal(KevFixtures.Day("2026-07-15"), single.UpdateDates["SQL Server"]);
        // With several instances the least recently updated binary decides.
        Assert.Equal(KevFixtures.Day("2019-09-24"), several.UpdateDates["SQL Server"]);
    }

    [Fact]
    public void Server_Products_Use_The_Newer_Of_Binary_And_Title_Dates()
    {
        var history = new[] { Update("Security Update for Exchange Server 2019 Cumulative Update 14 (KB5049233)", "2026-05-12") };

        var olderBinary = KevMatcher.ResolveProducts(new KevProductInventory { ExchangeInstalled = true, ExchangeServiceBinaryDate = KevFixtures.Day("2025-03-11") }, history);
        var newerBinary = KevMatcher.ResolveProducts(new KevProductInventory { ExchangeInstalled = true, ExchangeServiceBinaryDate = KevFixtures.Day("2026-08-12") }, history);
        var noDates = KevMatcher.ResolveProducts(new KevProductInventory { ExchangeInstalled = true }, []);

        Assert.Equal(KevFixtures.Day("2026-05-12"), olderBinary.UpdateDates["Exchange"]);
        Assert.Equal(KevFixtures.Day("2026-08-12"), newerBinary.UpdateDates["Exchange"]);
        Assert.Null(noDates.UpdateDates["Exchange"]);
    }

    [Fact]
    public void Office_Uses_Its_Click_To_Run_Build_And_Dot_Net_Its_Own_Titles()
    {
        var history = new[]
        {
            Update("9PLL735RFDSM-Microsoft.NET.Native.Runtime.2.2", "2026-09-20"),
            Update("2026-09 .NET Framework Security Update (KB5126052)", "2026-09-08"),
            Update("Security Update for Microsoft Office 2016 (KB5002700) 64-Bit Edition", "2026-04-14"),
        };
        var inventory = new KevProductInventory
        {
            DotNetFrameworkInstalled = true,
            OfficeInstalled = true,
            OfficeClickToRunBinaryDates = [KevFixtures.Day("2026-09-26"), KevFixtures.Day("2026-09-25")],
            IisInstalled = true,
            EdgeInstalled = true,
            EdgeBinaryDate = KevFixtures.Day("2026-09-25").AddHours(9),
        };

        var products = KevMatcher.ResolveProducts(inventory, history);

        Assert.Equal(new[] { "Windows", "IIS", ".NET", "Office", "Edge" }, products.Families);
        Assert.Equal(KevFixtures.Day("2026-09-08"), products.UpdateDates[".NET"]);
        Assert.Equal(KevFixtures.Day("2026-09-26"), products.UpdateDates["Office"]);
        Assert.Equal(KevFixtures.Day("2026-09-25"), products.UpdateDates["Edge"]);
        Assert.False(products.UpdateDates.ContainsKey("IIS"));
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\Microsoft SQL Server\\MSSQL15.SQLEXPRESS\\MSSQL\\Binn\\sqlservr.exe\" -sSQLEXPRESS", "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.SQLEXPRESS\\MSSQL\\Binn\\sqlservr.exe")]
    [InlineData("C:\\Exchange\\Bin\\Microsoft.Exchange.Store.Service.EXE -wait", "C:\\Exchange\\Bin\\Microsoft.Exchange.Store.Service.EXE")]
    [InlineData("%SystemRoot%\\system32\\svchost.exe -k iissvcs", "%SystemRoot%\\system32\\svchost.exe")]
    [InlineData("", null)]
    [InlineData("no executable here", null)]
    public void Service_Executable_Comes_From_The_Image_Path(string imagePath, string? expected)
    {
        Assert.Equal(expected, KevProductInventoryReader.ExecutableFromImagePath(imagePath));
    }

    [Fact]
    public void Inventory_Reader_Detects_Products_Like_The_PowerShell_Check()
    {
        const string sqlExe = @"C:\SQL\MSSQL15.SQLEXPRESS\Binn\sqlservr.exe";
        const string sqlDefaultExe = @"C:\SQL\MSSQL16.MSSQLSERVER\Binn\sqlservr.exe";
        const string exchangeExe = @"C:\Exchange\Bin\Microsoft.Exchange.Store.Service.exe";
        var registry = new FixtureRegistryReader()
            .Set($@"{KevProductInventoryReader.ServicesKey}\MSSQL$SQLEXPRESS", "ImagePath", $"\"{sqlExe}\" -sSQLEXPRESS")
            .Set($@"{KevProductInventoryReader.ServicesKey}\MSSQLSERVER", "ImagePath", $"\"{sqlDefaultExe}\" -sMSSQLSERVER")
            .Set($@"{KevProductInventoryReader.ServicesKey}\MSExchangeIS", "ImagePath", $"\"{exchangeExe}\"")
            .Set($@"{KevProductInventoryReader.DotNetFrameworkKey}\1033", "Version", "4.8.09032")
            .Set(KevProductInventoryReader.ClickToRunKey, "InstallationPath", @"C:\Program Files\Microsoft Office")
            .Set(KevProductInventoryReader.EdgeBeaconKey, "version", "140.0.3485.94");
        var files = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase)
        {
            [sqlExe] = new(2019, 9, 24, 15, 9, 8),
            [sqlDefaultExe] = new(2026, 7, 15, 3, 0, 0),
            [exchangeExe] = new(2026, 5, 12, 23, 0, 0),
            [@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"] = new(2026, 9, 26, 12, 11, 53),
            [@"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"] = new(2026, 9, 26, 12, 11, 51),
            [@"C:\PF86\Microsoft\Edge\Application\msedge.exe"] = new(2026, 9, 25, 8, 0, 0),
        };
        var reader = new KevProductInventoryReader(
            registry,
            () => ["Dnscache", "MSSQL$SQLEXPRESS", "MSSQLSERVER", "MSSQLFDLauncher", "MSExchangeIS", "W3SVC"],
            path => files.TryGetValue(path, out var d) ? d : null,
            name => name == "ProgramFiles(x86)" ? @"C:\PF86" : name == "ProgramFiles" ? @"C:\PF" : null);

        var inventory = reader.Read();

        Assert.True(inventory.ExchangeInstalled);
        Assert.Equal(new DateTime(2026, 5, 12), inventory.ExchangeServiceBinaryDate);
        Assert.Equal(2, inventory.SqlInstanceCount);
        Assert.Equal(new DateTime(2019, 9, 24), inventory.SqlOldestServiceBinaryDate);
        Assert.True(inventory.IisInstalled);
        Assert.True(inventory.DotNetFrameworkInstalled);
        Assert.True(inventory.OfficeInstalled);
        Assert.Equal(new[] { new DateTime(2026, 9, 26), new DateTime(2026, 9, 26) }, inventory.OfficeClickToRunBinaryDates);
        Assert.True(inventory.EdgeInstalled);
        Assert.Equal(new DateTime(2026, 9, 25), inventory.EdgeBinaryDate);
    }

    [Fact]
    public void Inventory_Reader_On_A_Bare_Host_Finds_Only_Windows()
    {
        var reader = new KevProductInventoryReader(
            new FixtureRegistryReader().AddKeyReturning(KevProductInventoryReader.DotNetFrameworkKey),
            () => ["Dnscache"],
            _ => null,
            _ => null);

        var inventory = reader.Read();
        var products = KevMatcher.ResolveProducts(inventory, []);

        // The .NET key with no subkeys doesn't count, matching Get-ChildItem in the PowerShell check.
        Assert.False(inventory.DotNetFrameworkInstalled);
        Assert.Equal(new[] { "Windows" }, products.Families);
    }
}

internal static class FixtureRegistryReaderKevExtensions
{
    public static FixtureRegistryReader AddKeyReturning(this FixtureRegistryReader registry, string keyPath)
    {
        registry.AddKey(keyPath);
        return registry;
    }
}

public sealed class KevCatalogServiceTests : IDisposable
{
    private readonly string _cacheDir = Path.Combine(Path.GetTempPath(), "nsa-kev-tests", Guid.NewGuid().ToString("N"));
    private readonly DateTime _now = new(2026, 9, 30, 12, 0, 0, DateTimeKind.Utc);
    private int _downloads;

    public void Dispose()
    {
        try { Directory.Delete(_cacheDir, recursive: true); } catch (DirectoryNotFoundException) { }
    }

    private KevCatalogService Service(Func<CancellationToken, Task<string>> download, int minimumEntries = 10) =>
        new(ct => { _downloads++; return download(ct); }, _cacheDir, () => _now, minimumEntries);

    private static Task<string> Fixture(CancellationToken _) => Task.FromResult(KevFixtures.FeedText);

    private static Task<string> Unreachable(CancellationToken _) => throw new HttpRequestException("No such host is known. (www.cisa.gov:443)");

    private void WriteCache(double hoursOld)
    {
        Directory.CreateDirectory(_cacheDir);
        var path = Path.Combine(_cacheDir, KevCatalogService.CacheFileName);
        File.WriteAllText(path, KevFixtures.FeedText);
        File.SetLastWriteTimeUtc(path, _now.AddHours(-hoursOld));
    }

    [Fact]
    public async Task Offline_Without_A_Cache_Skips_With_OfflineMode_And_Never_Downloads()
    {
        var load = await Service(Fixture).LoadAsync(offline: true, CancellationToken.None);

        Assert.Null(load.Catalog);
        Assert.Equal(KevCatalogService.OfflineMode, load.SkipReason);
        Assert.Equal(0, _downloads);
    }

    [Fact]
    public async Task Offline_With_A_Cache_Uses_It_Whatever_Its_Age()
    {
        WriteCache(hoursOld: 72.26);

        var load = await Service(Fixture).LoadAsync(offline: true, CancellationToken.None);

        Assert.Equal(12, load.Catalog!.Entries.Count);
        Assert.Equal(KevCatalogService.OfflineMode, load.SkipReason);
        Assert.Equal("cache (72.3 hours old)", load.Source);
        Assert.Equal(0, _downloads);
    }

    [Fact]
    public async Task A_Cache_Under_A_Day_Old_Is_Used_Without_Downloading()
    {
        WriteCache(hoursOld: 2.9);

        var load = await Service(Fixture).LoadAsync(offline: false, CancellationToken.None);

        Assert.Equal("cache (2.9 hours old)", load.Source);
        Assert.Null(load.SkipReason);
        Assert.Equal(0, _downloads);
    }

    [Fact]
    public async Task An_Old_Cache_Is_Replaced_By_A_Download()
    {
        WriteCache(hoursOld: 30);
        File.WriteAllText(Path.Combine(_cacheDir, KevCatalogService.CacheFileName), "{\"vulnerabilities\":[]}");
        File.SetLastWriteTimeUtc(Path.Combine(_cacheDir, KevCatalogService.CacheFileName), _now.AddHours(-30));

        var load = await Service(Fixture).LoadAsync(offline: false, CancellationToken.None);

        Assert.Equal("live download", load.Source);
        Assert.Equal(1, _downloads);
        Assert.False(load.Rejected);
        Assert.Equal(KevFixtures.FeedText, File.ReadAllText(load.CachePath));
    }

    [Fact]
    public async Task A_Failed_Download_Falls_Back_To_The_Cache_And_Says_How_Old_It_Is()
    {
        WriteCache(hoursOld: 30.04);

        var load = await Service(Unreachable).LoadAsync(offline: false, CancellationToken.None);

        Assert.Equal(12, load.Catalog!.Entries.Count);
        Assert.Equal("stale cache (30 hours, download failed)", load.Source);
        Assert.Contains("No such host is known", load.Detail);
    }

    [Fact]
    public async Task A_Failed_Download_Without_A_Cache_Reports_The_Feed_Unavailable()
    {
        var load = await Service(Unreachable).LoadAsync(offline: false, CancellationToken.None);

        Assert.Null(load.Catalog);
        Assert.Equal(KevCatalogService.FeedUnavailable, load.SkipReason);
        Assert.Contains("No such host is known", load.Detail);
    }

    [Fact]
    public async Task A_Download_Timeout_Is_Reported_As_One()
    {
        var load = await Service(_ => throw new TaskCanceledException()).LoadAsync(offline: false, CancellationToken.None);

        Assert.Equal(KevCatalogService.FeedUnavailable, load.SkipReason);
        Assert.Equal("download timed out after 30s", load.Detail);
    }

    [Fact]
    public async Task A_Truncated_Feed_Is_Rejected_And_Not_Cached()
    {
        var load = await Service(Fixture, minimumEntries: KevCatalogService.DefaultMinimumEntries).LoadAsync(offline: false, CancellationToken.None);

        Assert.True(load.Rejected);
        Assert.False(File.Exists(load.CachePath));
    }

    [Fact]
    public async Task The_Download_Is_Bounded()
    {
        using var big = new MemoryStream(Encoding.UTF8.GetBytes(new string(' ', 2048)));

        await Assert.ThrowsAsync<InvalidDataException>(() => KevCatalogService.ReadBoundedAsync(big, 1024, CancellationToken.None));
        Assert.True(KevCatalogService.MaxFeedBytes >= 8 * 1024 * 1024);
        Assert.Equal(TimeSpan.FromSeconds(30), KevCatalogService.DownloadTimeout);
    }

    [Fact]
    public void The_Cache_Lives_In_The_App_Data_Folder()
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkSecurityAuditor", KevCatalogService.CacheFileName);

        Assert.Equal(expected, new KevCatalogService().CachePath);
    }
}

public sealed class EP04KevAssessmentTests
{
    private static readonly DateOnly Today = new(2026, 9, 30);

    /// <summary>This PC as the PowerShell EP04 check saw it on 2026-09-30: patched 8 days earlier, SQL Server Express on its 2019 build.</summary>
    private static EP04_PatchComplianceCheck.PatchSnapshot ThisPc(KevCatalogLoad? kev) => new()
    {
        Hotfixes = [new EP04_PatchComplianceCheck.HotfixInfo("KB5129195", new DateTime(2026, 9, 22), "Security Update")],
        UpdateHistory =
        [
            new EP04_PatchComplianceCheck.UpdateHistoryEntry("2026-09 .NET Framework Security Update (KB5126052)", new DateTime(2026, 9, 8, 21, 40, 0)),
            new EP04_PatchComplianceCheck.UpdateHistoryEntry("9PLL735RFDSM-Microsoft.NET.Native.Runtime.2.2", new DateTime(2026, 9, 20, 14, 5, 0)),
        ],
        OsCaption = "Microsoft Windows 11 Pro",
        OsBuild = 26200,
        OsVersion = "10.0.26200",
        Products = new KevProductInventory
        {
            SqlInstanceCount = 1,
            SqlOldestServiceBinaryDate = new DateTime(2019, 9, 24),
            DotNetFrameworkInstalled = true,
            OfficeInstalled = true,
            OfficeClickToRunBinaryDates = [new DateTime(2026, 9, 26)],
        },
        Kev = kev,
    };

    private static KevCatalogLoad Live(KevCatalog? catalog = null) => new() { Catalog = catalog ?? KevFixtures.Catalog, Source = "live download", MinimumEntries = 10 };

    [Fact]
    public void Lists_Matches_With_Cve_And_Due_Date_Like_The_PowerShell_Check_On_This_Pc()
    {
        var assessment = EP04_PatchComplianceCheck.Assess(ThisPc(Live()), Today);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        // These lines are what the PowerShell EP04 check printed on this PC on 2026-09-30.
        Assert.Contains("  Detected products: Windows, SQL Server, .NET, Office", assessment.Findings);
        Assert.Contains("  Newest update per product: Windows 2026-09-22, SQL Server 2019-09-24, .NET 2026-09-08, Office 2026-09-26. KEV entries added before that are treated as fixed.", assessment.Findings);
        Assert.Contains("  KEV entries newer than this host's updates: 1 (overdue: 1, ransomware-linked: 0)", assessment.Findings);
        Assert.Contains("    CVE-2019-1068 | SQL Server | Microsoft SQL Server Remote Code Execution Vulnerability | Added: 2026-08-26 | Due: 2026-08-29 [OVERDUE]", assessment.Findings);
        Assert.Contains("  Ransomware-linked KEV entries: 0 (overdue: 0)", assessment.Findings);
        Assert.Contains("  KEV catalog: 12 known exploited vulnerabilities (source: live download)", assessment.Findings);
        Assert.Contains("  Catalog version: 2026.09.29", assessment.Findings);
    }

    [Fact]
    public void A_Host_Patched_After_Every_Entry_Passes()
    {
        var snapshot = ThisPc(Live()) with { Products = new KevProductInventory { DotNetFrameworkInstalled = true } };

        var assessment = EP04_PatchComplianceCheck.Assess(snapshot, Today);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("No KEV entries newer than this host's updates for detected products [OK]", assessment.Findings);
    }

    [Fact]
    public void An_Overdue_Ransomware_Linked_Entry_Fails_And_One_Not_Yet_Due_Warns()
    {
        var exchange = new KevProductInventory { ExchangeInstalled = true, ExchangeServiceBinaryDate = new DateTime(2024, 6, 11) };

        var overdue = EP04_PatchComplianceCheck.Assess(ThisPc(Live()) with { Products = exchange }, Today);
        var early = EP04_PatchComplianceCheck.Assess(
            ThisPc(Live()) with { Products = exchange, Hotfixes = [new EP04_PatchComplianceCheck.HotfixInfo("KB5055523", new DateTime(2026, 4, 14), "Security Update")], UpdateHistory = [] },
            new DateOnly(2026, 4, 20));

        Assert.Equal(CheckStatus.Fail, overdue.Status);
        Assert.Contains("FAIL: 1 ransomware-linked KEV entry is past the CISA due date.", overdue.Findings);
        Assert.Contains("CVE-2023-21529 | Exchange Server | Microsoft Exchange Server Deserialization of Untrusted Data Vulnerability | Added: 2026-04-13 | Due: 2026-04-27 [OVERDUE] [RANSOMWARE]", overdue.Findings);
        Assert.Contains("Ransomware-linked KEV entries: 1 (overdue: 1)", overdue.Findings);

        Assert.Equal(CheckStatus.Partial, early.Status);
        Assert.Contains("WARNING: 1 ransomware-linked KEV entry isn't due yet.", early.Findings);
        Assert.Contains("Ransomware-linked KEV entries: 1 (overdue: 0)", early.Findings);
    }

    [Fact]
    public void A_Product_With_No_Update_Date_Is_Flagged_As_Unverified()
    {
        var snapshot = ThisPc(Live()) with { Products = new KevProductInventory { SqlInstanceCount = 3 } };

        var assessment = EP04_PatchComplianceCheck.Assess(snapshot, Today);

        Assert.Contains("SQL Server unknown", assessment.Findings);
        Assert.Contains("Due: 2026-08-29 [OVERDUE] [no SQL Server update date to compare]", assessment.Findings);
    }

    [Fact]
    public void Offline_Without_A_Cache_Reports_Skipped_OfflineMode_And_Leaves_The_Status_Alone()
    {
        var kev = new KevCatalogLoad { SkipReason = KevCatalogService.OfflineMode, Detail = "no local KEV cache", CachePath = @"C:\cache\cisa-kev-cache.json" };

        var assessment = EP04_PatchComplianceCheck.Assess(ThisPc(kev), Today);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Skipped: OfflineMode. There's no local KEV cache to fall back on.", assessment.Findings);
        Assert.DoesNotContain("Ransomware-linked KEV entries", assessment.Findings);
        Assert.Contains(@"Cache: C:\cache\cisa-kev-cache.json (none)", assessment.Evidence);
    }

    [Fact]
    public void Offline_With_A_Cache_Reports_Its_Age_And_Still_Matches()
    {
        var kev = Live() with { Source = "cache (5.2 hours old)", SkipReason = KevCatalogService.OfflineMode, CacheAgeHours = 5.2 };

        var assessment = EP04_PatchComplianceCheck.Assess(ThisPc(kev), Today);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("Skipped: OfflineMode. The feed wasn't downloaded; using the local cache (5.2 hours old).", assessment.Findings);
        Assert.Contains("(source: cache (5.2 hours old))", assessment.Findings);
        Assert.Contains("CVE-2019-1068", assessment.Findings);
    }

    [Fact]
    public void An_Unavailable_Feed_Or_A_Truncated_One_Is_Said_Plainly()
    {
        var unavailable = EP04_PatchComplianceCheck.Assess(ThisPc(new KevCatalogLoad { SkipReason = KevCatalogService.FeedUnavailable, Detail = "download timed out after 30s" }), Today);
        var stale = EP04_PatchComplianceCheck.Assess(ThisPc(Live() with { Source = "stale cache (30 hours, download failed)", Detail = "download timed out after 30s" }), Today);
        var rejected = EP04_PatchComplianceCheck.Assess(ThisPc(Live() with { Rejected = true, MinimumEntries = 100 }), Today);

        Assert.Equal(CheckStatus.Pass, unavailable.Status);
        Assert.Contains("KEV check skipped: the feed is unavailable and there's no local cache (download timed out after 30s).", unavailable.Findings);
        Assert.Contains("(source: stale cache (30 hours, download failed))", stale.Findings);
        Assert.Contains("KEV catalog rejected: only 12 entries (expected 100+, possible corrupt data)", rejected.Findings);
        Assert.Equal(CheckStatus.Pass, rejected.Status);
    }

    [Fact]
    public async Task ExecuteAsync_Uses_The_Injected_Host_Feed_And_Clock()
    {
        var cacheDir = Path.Combine(Path.GetTempPath(), "nsa-kev-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var downloads = 0;
            var kev = new KevCatalogService(_ => { downloads++; return Task.FromResult(KevFixtures.FeedText); }, cacheDir, () => new DateTime(2026, 9, 30, 16, 0, 0, DateTimeKind.Utc), minimumEntries: 10);
            var check = new EP04_PatchComplianceCheck((_, _) => ThisPc(null), kev, () => new DateTime(2026, 9, 30, 12, 0, 0));

            var online = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
            var offline = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions { NoInternet = true }, CancellationToken.None);

            Assert.Equal(CheckStatus.Partial, online.Status);
            Assert.Contains("(source: live download)", online.Findings);
            Assert.Contains("Skipped: OfflineMode. The feed wasn't downloaded; using the local cache (", offline.Findings);
            Assert.Equal(1, downloads);
        }
        finally
        {
            try { Directory.Delete(cacheDir, recursive: true); } catch (DirectoryNotFoundException) { }
        }
    }
}

public sealed class RansomwareKevScoringTests
{
    private static CheckItemViewModel Vm(string id, CheckStatus status, string findings = "") => new()
    {
        Id = id,
        Label = id,
        Category = "Test",
        Severity = Severity.High,
        Status = status,
        Findings = findings,
    };

    private static List<CheckItemViewModel> Prevention(CheckItemViewModel? ep04)
    {
        var checks = new List<CheckItemViewModel>
        {
            Vm("EP01", CheckStatus.Pass), Vm("EP07", CheckStatus.Pass), Vm("CF02", CheckStatus.Pass), Vm("NP05", CheckStatus.Pass),
        };
        if (ep04 is not null)
            checks.Add(ep04);
        return checks;
    }

    [Fact]
    public void Ransomware_Linked_Kev_Entries_Lower_The_Prevention_Score()
    {
        var clean = RansomwareReadinessEngine.Calculate(Prevention(Vm("EP04", CheckStatus.Pass, "  Ransomware-linked KEV entries: 0 (overdue: 0)")));
        var notDue = RansomwareReadinessEngine.Calculate(Prevention(Vm("EP04", CheckStatus.Partial, "  Ransomware-linked KEV entries: 1 (overdue: 0)")));
        var overdue = RansomwareReadinessEngine.Calculate(Prevention(Vm("EP04", CheckStatus.Fail, "  Ransomware-linked KEV entries: 2 (overdue: 1)")));

        Assert.Equal((100, "A"), clean);
        Assert.Equal((90, "A"), notDue);
        Assert.Equal((80, "B"), overdue);
    }

    [Fact]
    public void Without_A_Kev_Result_Ep04_Leaves_The_Score_Alone()
    {
        var baseline = RansomwareReadinessEngine.Calculate(Prevention(null));

        Assert.Equal(baseline, RansomwareReadinessEngine.Calculate(Prevention(Vm("EP04", CheckStatus.Fail, "  Skipped: OfflineMode. There's no local KEV cache to fall back on."))));
        Assert.Equal(baseline, RansomwareReadinessEngine.Calculate(Prevention(Vm("EP04", CheckStatus.Error, "  Ransomware-linked KEV entries: 1 (overdue: 1)"))));
    }

    [Fact]
    public void Ep04_Findings_Feed_The_Ransomware_Score()
    {
        var exchange = new KevProductInventory { ExchangeInstalled = true, ExchangeServiceBinaryDate = new DateTime(2024, 6, 11) };
        var snapshot = new EP04_PatchComplianceCheck.PatchSnapshot
        {
            Hotfixes = [new EP04_PatchComplianceCheck.HotfixInfo("KB5129195", new DateTime(2026, 9, 22), "Security Update")],
            OsCaption = "Microsoft Windows Server 2022 Standard",
            OsBuild = 20348,
            Products = exchange,
            Kev = new KevCatalogLoad { Catalog = KevFixtures.Catalog, Source = "live download", MinimumEntries = 10 },
        };
        var assessment = EP04_PatchComplianceCheck.Assess(snapshot, new DateOnly(2026, 9, 30));

        Assert.True(RansomwareReadinessEngine.TryReadKevExposure(assessment.Findings, out var linked, out var overdue));
        Assert.Equal((1, 1), (linked, overdue));
        Assert.Equal((double?)0.0, RansomwareReadinessEngine.KevExposureFactor(Vm("EP04", assessment.Status, assessment.Findings)));
    }
}

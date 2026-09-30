using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using Xunit.Abstractions;
using AdComputer = NetworkSecurityAuditor.Checks.EndpointSecurity.EP10_EolOsCheck.AdComputer;
using Product = NetworkSecurityAuditor.Checks.EndpointSecurity.EP10_EolOsCheck.InstalledProduct;
using Snapshot = NetworkSecurityAuditor.Checks.EndpointSecurity.EP10_EolOsCheck.EolSnapshot;

namespace NetworkSecurityAuditor.Tests;

public class EP10EolOsCheckTests(ITestOutputHelper output)
{
    private static readonly DateOnly Today = new(2026, 9, 30);

    private static Snapshot Win11Pro25H2() => new() { OsCaption = "Microsoft Windows 11 Pro", OsBuild = 26200 };

    private static Snapshot Win10Pro(EsuEnrollment esu, DateOnly? until = null) => new()
    {
        OsCaption = "Microsoft Windows 10 Pro",
        OsBuild = 19045,
        Windows10Esu = esu,
        EsuCoversUntil = until,
    };

    [Fact]
    public void Supported_Workgroup_Host_Passes_Without_A_Directory()
    {
        var assessment = EP10_EolOsCheck.Assess(Win11Pro25H2(), Today);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Windows 11 25H2 (Home/Pro): supported until 2027-10-12", assessment.Findings);
        Assert.Contains("isn't domain-joined", assessment.Evidence);
    }

    [Fact]
    public void Workgroup_Host_On_An_Ended_Release_Fails()
    {
        var assessment = EP10_EolOsCheck.Assess(new Snapshot { OsCaption = "Microsoft Windows 8.1 Pro", OsBuild = 9600 }, Today);

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("FAIL: Local OS Windows 8.1: end of support 2023-01-10", assessment.Findings);
    }

    [Fact]
    public void Esu_Enrolled_Windows10_Is_Partial_With_The_Esu_End_Date()
    {
        var assessment = EP10_EolOsCheck.Assess(Win10Pro(EsuEnrollment.Enrolled, new DateOnly(2026, 10, 13)), Today);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("covered by Extended Security Updates until 2026-10-13", assessment.Findings);
    }

    [Fact]
    public void Windows10_Without_An_Esu_License_Fails_And_Explains_Consumer_Esu()
    {
        var assessment = EP10_EolOsCheck.Assess(Win10Pro(EsuEnrollment.NotEnrolled), Today);

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("not enrolled in Extended Security Updates", assessment.Findings);
        Assert.Contains("Consumer ESU enrollment", assessment.Findings);
    }

    [Fact]
    public void Unreadable_Esu_License_Is_Partial_Not_Pass_Or_Fail()
    {
        var assessment = EP10_EolOsCheck.Assess(Win10Pro(EsuEnrollment.Unknown), Today);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("enrollment can't be confirmed here", assessment.Findings);
    }

    [Fact]
    public void Local_Products_Are_Judged_Against_The_Table()
    {
        var office = EP10_EolOsCheck.Assess(Win11Pro25H2() with { Products = [new Product("Office 2019", "Microsoft Office Professional Plus 2019 - en-us")] }, Today);
        var sql = EP10_EolOsCheck.Assess(Win11Pro25H2() with { Products = [new Product("SQL Server 2016", "instance MSSQLSERVER, 13.0.6300.2")] }, Today);
        var current = EP10_EolOsCheck.Assess(Win11Pro25H2() with
        {
            Products = [new Product("SQL Server 2019", "instance SQLEXPRESS, 15.0.2000.5"), new Product("Exchange Server Subscription Edition", "v15")],
        }, Today);

        Assert.Equal(CheckStatus.Fail, office.Status);
        Assert.Contains("FAIL: Office 2019: end of support 2025-10-14", office.Findings);
        Assert.Equal(CheckStatus.Partial, sql.Status);
        Assert.Contains("SQL Server 2016: past end of support (2026-07-14)", sql.Findings);
        Assert.Equal(CheckStatus.Pass, current.Status);
        Assert.Contains("Exchange Server Subscription Edition (v15): Unknown", current.Evidence);
    }

    [Fact]
    public void Directory_Sweep_Flags_Ended_Releases_And_Asks_To_Confirm_Esu()
    {
        var computers = new List<AdComputer>();
        for (var i = 0; i < 3; i++) computers.Add(new($"LEGACY{i}", "Windows 7 Professional", "6.1 (7601)"));
        for (var i = 0; i < 5; i++) computers.Add(new($"WS10-{i}", "Windows 10 Enterprise", "10.0 (19045)"));
        for (var i = 0; i < 10; i++) computers.Add(new($"WS11-{i}", "Windows 11 Enterprise", "10.0 (26100)"));

        var assessment = EP10_EolOsCheck.Assess(Win11Pro25H2() with { DomainJoined = true, AdComputers = computers }, Today);

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("FAIL: 3 enabled computer(s) run software past end of support", assessment.Findings);
        Assert.Contains("PARTIAL: 5 enabled computer(s) are past end of support but inside an Extended Security Updates window", assessment.Findings);
        Assert.Contains("Windows 10 to 11 migration: 66% (10/15", assessment.Findings);
        Assert.Contains("LEGACY0 | Windows 7 Professional", assessment.Evidence);
    }

    [Fact]
    public void Failed_Directory_Query_Leaves_The_Local_Result()
    {
        var assessment = EP10_EolOsCheck.Assess(Win11Pro25H2() with { DomainJoined = true, AdError = "The server is not operational." }, Today);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Couldn't query AD computer objects", assessment.Findings);
    }

    [Fact]
    public void Ep10_Runs_On_Workgroup_Hosts()
    {
        Assert.Equal(CheckType.Local, CheckCatalog.All["EP10"].Type);
        var applicable = CheckRunner.ResolveApplicableCheckIds(new EnvironmentInfo { IsDomainJoined = false }, new AuditOptions { ScanProfile = ScanProfileType.LocalOnly });
        Assert.Contains("EP10", applicable);
        Assert.Contains("(!(userAccountControl:1.2.840.113556.1.4.803:=2))", EP10_EolOsCheck.AdComputerFilter);
    }

    [Theory]
    [InlineData("MSSQL13.MSSQLSERVER", "13.0.6300.2", "SQL Server 2016")]
    [InlineData("MSSQL15.SQLEXPRESS", null, "SQL Server 2019")]
    [InlineData("MSSQL11.MSSQLSERVER", "11.0.7001.0", "SQL Server 2012 or older")]
    [InlineData("MSSQL16.MSSQLSERVER", "16.0.1000.6", "SQL Server 2022")]
    public void Maps_Sql_Server_Versions(string instanceId, string? version, string expected)
    {
        Assert.Equal(expected, EP10_EolOsCheck.SqlProductName(instanceId, version));
    }

    [Theory]
    [InlineData("Microsoft Office Professional Plus 2016", "Office 2016")]
    [InlineData("Microsoft Office Home and Business 2019 - en-us", "Office 2019")]
    [InlineData("Microsoft Office 2016 Language Pack - French", null)]
    [InlineData("Microsoft 365 Apps for enterprise - en-us", null)]
    [InlineData("Microsoft Office Professional Plus 2021 - en-us", null)]
    public void Maps_Office_Installs(string displayName, string? expected)
    {
        Assert.Equal(expected, EP10_EolOsCheck.OfficeProductName(displayName));
    }

    [Theory]
    [InlineData(15, 1, 225, "Exchange Server 2016")]
    [InlineData(15, 2, 1748, "Exchange Server 2019")]
    [InlineData(15, 2, 2562, "Exchange Server Subscription Edition")]
    [InlineData(15, 2, -1, "Exchange Server 2019 or Subscription Edition (build unknown)")]
    [InlineData(-1, -1, -1, null)]
    public void Maps_Exchange_Versions(int major, int minor, int build, string? expected)
    {
        Assert.Equal(expected, EP10_EolOsCheck.ExchangeProductName(major, minor, build));
    }

    [Fact]
    public void Esu_License_Is_Read_By_Activation_Id_Or_Name()
    {
        var byId = EsuLicenseReader.Evaluate([("1043add5-23b1-4afb-9a0f-64343c8f3f8d", "Windows(R), ESU add-on")]);
        Assert.Equal(EsuEnrollment.Enrolled, byId.Enrollment);
        Assert.Equal(new DateOnly(2027, 10, 12), byId.CoversUntil);

        var byName = EsuLicenseReader.Evaluate([("00000000-0000-0000-0000-000000000001", "Windows(R), Client-ESU-Year1 add-on for Client")]);
        Assert.Equal(new DateOnly(2026, 10, 13), byName.CoversUntil);

        Assert.Equal(EsuEnrollment.NotEnrolled, EsuLicenseReader.Evaluate([("55c92734-d682-4d71-983e-d6ec3f16059f", "Windows(R), Professional edition")]).Enrollment);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var env = NetworkSecurityAuditor.Services.EnvironmentDetector.Detect();
        var result = await new EP10_EolOsCheck().ExecuteAsync(env, new AuditOptions(), CancellationToken.None);
        output.WriteLine($"{result.Status}\n{result.Findings}\n{result.Evidence}");

        Assert.Null(result.Error);
        Assert.Contains("[Lifecycle Table]", result.Evidence);
        Assert.Contains("[Local Products]", result.Evidence);
    }

    private static EnvironmentInfo Win11DomainMember()
    {
        var env = FixtureDirectoryReader.DomainMember;
        env.OSCaption = "Microsoft Windows 11 Pro";
        env.OSBuild = 26200;
        return env;
    }

    // The local SQL/Office/Exchange scan reads this host's registry, so the directory verdicts are judged without it.
    private static Snapshot CollectFromFixture(string fixture) =>
        EP10_EolOsCheck.CollectSnapshot(Win11DomainMember(), _ => FixtureDirectoryReader.Load(fixture), CancellationToken.None) with { Products = [] };

    [Fact]
    public void Directory_Sweep_Searches_Under_The_Default_Naming_Context()
    {
        var directory = FixtureDirectoryReader.Load("EP10-fail.json");

        var computers = EP10_EolOsCheck.QueryAdComputers(directory, CancellationToken.None);

        Assert.Equal(9, computers.Count);
        Assert.Contains(computers, c => c.Name == "LEGACY01" && c.OperatingSystem == "Windows 7 Professional" && c.OperatingSystemVersion == "6.1 (7601)");
        Assert.Contains(computers, c => c.Name == "NAS01" && c.OperatingSystem is null && c.OperatingSystemVersion is null);
        var query = Assert.Single(directory.Queries);
        Assert.Equal("DC=corp,DC=example", query.SearchBase);
        Assert.Equal(EP10_EolOsCheck.AdComputerFilter, query.Filter);
        Assert.Equal(new[] { "name", "operatingSystem", "operatingSystemVersion" }, query.Properties);
    }

    [Fact]
    public void Fixture_Directory_Of_Supported_Releases_Passes()
    {
        var snapshot = CollectFromFixture("EP10-pass.json");
        var assessment = EP10_EolOsCheck.Assess(snapshot, Today);

        Assert.Equal(6, snapshot.AdComputers!.Count);
        Assert.Null(snapshot.AdError);
        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("AD: 6 enabled computers evaluated.", assessment.Findings);
        Assert.Contains("Windows 10 to 11 migration: 100% (4/4 workstations on Windows 11).", assessment.Findings);
        Assert.DoesNotContain("past end of support", assessment.Findings);
    }

    [Fact]
    public void Fixture_Directory_With_Windows10_Awaiting_Esu_Is_Partial()
    {
        var assessment = EP10_EolOsCheck.Assess(CollectFromFixture("EP10-partial.json"), Today);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("PARTIAL: 2 enabled computer(s) are past end of support but inside an Extended Security Updates window", assessment.Findings);
    }

    [Fact]
    public void Fixture_Directory_With_Ended_Releases_Fails()
    {
        var assessment = EP10_EolOsCheck.Assess(CollectFromFixture("EP10-fail.json"), Today);

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("AD: 9 enabled computers evaluated.", assessment.Findings);
        Assert.Contains("FAIL: 2 enabled computer(s) run software past end of support:", assessment.Findings);
        Assert.Contains("LEGACY01 | Windows 7 Professional", assessment.Evidence);
        Assert.Contains("FILE01 | Windows Server 2008 R2 Standard", assessment.Evidence);
        Assert.Contains("1 x Unknown: Unknown", assessment.Evidence);
    }

    [Fact]
    public async Task Fixture_Directory_With_Ended_Releases_Fails_End_To_End()
    {
        var result = await new EP10_EolOsCheck(_ => FixtureDirectoryReader.Load("EP10-fail.json"))
            .ExecuteAsync(Win11DomainMember(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: 2 enabled computer(s) run software past end of support:", result.Findings);
    }

    [Fact]
    public void RootDse_Without_A_Naming_Context_Is_Reported_As_A_Directory_Error()
    {
        var snapshot = CollectFromFixture("EP10-no-naming-context.json");

        Assert.Null(snapshot.AdComputers);
        Assert.Equal("RootDSE returned no defaultNamingContext.", snapshot.AdError);
    }

    [Fact]
    public async Task Directory_Failure_Keeps_The_Local_Result()
    {
        // EP10 is a local check first: a directory failure drops only the AD sweep.
        var result = await new EP10_EolOsCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(Win11DomainMember(), new AuditOptions(), CancellationToken.None);

        Assert.NotEqual(CheckStatus.Error, result.Status);
        Assert.Null(result.Error);
        Assert.Contains("INFO: Couldn't query AD computer objects, so only this host was evaluated.", result.Findings);
        Assert.Contains("Query failed: The server is not operational.", result.Evidence);
    }

    [Fact]
    public async Task Unexpected_Directory_Failure_Is_An_Error()
    {
        var result = await new EP10_EolOsCheck(_ => throw new NotSupportedException("The directory provider isn't available."))
            .ExecuteAsync(Win11DomainMember(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
        Assert.Equal("The directory provider isn't available.", result.Error);
    }
}

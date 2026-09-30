using System.Runtime.InteropServices;
using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;
using Computer = NetworkSecurityAuditor.Checks.IdentityAccess.IA06_PamCheck.LapsComputer;
using Snapshot = NetworkSecurityAuditor.Checks.IdentityAccess.IA06_PamCheck.LapsSnapshot;

namespace NetworkSecurityAuditor.Tests;

public class IA06PamCheckTests
{
    private static IReadOnlyList<Computer> Fleet(int windows, int legacy, int both, int none)
    {
        var list = new List<Computer>();
        var n = 0;
        string Dn() => $"CN=PC{++n:D3},OU=Workstations,DC=corp,DC=example";
        for (var i = 0; i < windows; i++) list.Add(new(Dn(), true, false));
        for (var i = 0; i < legacy; i++) list.Add(new(Dn(), false, true));
        for (var i = 0; i < both; i++) list.Add(new(Dn(), true, true));
        for (var i = 0; i < none; i++) list.Add(new(Dn(), false, false));
        return list;
    }

    private static Snapshot Extended(IReadOnlyList<Computer> computers) => new()
    {
        Computers = computers,
        WindowsLapsSchema = true,
        LegacyLapsSchema = true,
    };

    [Fact]
    public void Coverage_Is_The_Union_By_Distinguished_Name_Not_The_Larger_Count()
    {
        // 5 Windows LAPS only, 4 legacy only, 2 both, 9 without: union 11/20 = 55%, Math.Max would say 7.
        var assessment = IA06_PamCheck.Assess(Extended(Fleet(windows: 5, legacy: 4, both: 2, none: 9)));

        Assert.Equal(11, assessment.Covered);
        Assert.Equal(20, assessment.Total);
        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("55.0% (11/20", assessment.Findings);
        Assert.Contains("Both Windows LAPS and legacy LAPS are in use", assessment.Findings);
    }

    [Fact]
    public void Union_Pushes_A_Mixed_Fleet_Over_The_Threshold()
    {
        // 50 + 45 alone would read as 50/100 under Math.Max; the union is 95/100.
        var assessment = IA06_PamCheck.Assess(Extended(Fleet(windows: 50, legacy: 45, both: 0, none: 5)));

        Assert.Equal(95, assessment.Covered);
        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("PASS: LAPS coverage is 95.0%", assessment.Findings);
    }

    [Fact]
    public void Duplicate_Results_For_One_Computer_Count_Once()
    {
        var computers = new List<Computer>
        {
            new("CN=PC1,DC=corp,DC=example", true, false),
            new("cn=pc1,dc=corp,dc=example", false, true),
            new("CN=PC2,DC=corp,DC=example", false, false),
        };

        var assessment = IA06_PamCheck.Assess(Extended(computers));

        Assert.Equal(2, assessment.Total);
        Assert.Equal(1, assessment.Covered);
        Assert.Contains("CN=PC2,DC=corp,DC=example", assessment.Evidence);
    }

    [Fact]
    public void Schema_Without_Either_Attribute_Fails_As_Not_Extended()
    {
        var assessment = IA06_PamCheck.Assess(new Snapshot
        {
            Computers = Fleet(0, 0, 0, 12),
            WindowsLapsSchema = false,
            LegacyLapsSchema = false,
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("schema has neither the Windows LAPS nor the legacy LAPS attributes", assessment.Findings);
        Assert.Contains("not in schema", assessment.Evidence);
    }

    [Fact]
    public void Access_Denied_Search_Is_Not_Assessed_And_Names_The_Right()
    {
        var assessment = IA06_PamCheck.Assess(new Snapshot
        {
            Computers = null,
            SearchError = "Access is denied.",
            SearchAccessDenied = true,
            WindowsLapsSchema = true,
            LegacyLapsSchema = false,
        });

        Assert.Equal(CheckStatus.NotAssessed, assessment.Status);
        Assert.Contains("denied access to computer objects", assessment.Findings);
        Assert.Contains("needs Read on computer objects", assessment.Findings);
        Assert.Equal("Access is denied.", assessment.Error);
        Assert.DoesNotContain("No LAPS", assessment.Findings, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Zero_Coverage_With_The_Schema_Extended_Is_A_Distinct_Fail()
    {
        var assessment = IA06_PamCheck.Assess(Extended(Fleet(0, 0, 0, 30)));

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("schema is present, but none of the 30 enabled computers", assessment.Findings);
        Assert.DoesNotContain("schema has neither", assessment.Findings);
    }

    [Fact]
    public void Zero_Coverage_While_This_Machine_Backs_Up_To_AD_Is_Not_Assessed()
    {
        foreach (var snapshot in new[]
        {
            Extended(Fleet(0, 0, 0, 30)) with { LocalBackupDirectory = 2 },
            Extended(Fleet(0, 0, 0, 30)) with { LocalLegacyLapsEnabled = true },
        })
        {
            var assessment = IA06_PamCheck.Assess(snapshot);

            Assert.Equal(CheckStatus.NotAssessed, assessment.Status);
            Assert.Contains("most likely can't read it", assessment.Findings);
            Assert.Contains($"Read Property on {IA06_PamCheck.WindowsLapsExpiration} and {IA06_PamCheck.LegacyLapsExpiration}", assessment.Findings);
        }

        // Backing up to Entra ID says nothing about AD readability.
        Assert.Equal(CheckStatus.Fail, IA06_PamCheck.Assess(Extended(Fleet(0, 0, 0, 30)) with { LocalBackupDirectory = 1 }).Status);
    }

    [Fact]
    public void Unknown_Schema_With_Values_Still_Measures_Coverage()
    {
        var assessment = IA06_PamCheck.Assess(new Snapshot
        {
            Computers = Fleet(windows: 19, legacy: 0, both: 0, none: 1),
            SchemaError = "Access is denied.",
        });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Schema couldn't be read", assessment.Evidence);
    }

    [Fact]
    public void No_Member_Computers_Is_Not_Assessed()
    {
        var assessment = IA06_PamCheck.Assess(Extended([]));

        Assert.Equal(CheckStatus.NotAssessed, assessment.Status);
        Assert.Contains("returned no enabled computers", assessment.Findings);
    }

    [Fact]
    public void Legacy_Only_Fleet_Is_Flagged_For_Migration()
    {
        var assessment = IA06_PamCheck.Assess(Extended(Fleet(0, 20, 0, 0)));

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Only legacy LAPS is in use", assessment.Findings);
    }

    [Fact]
    public void Coverage_Never_Reads_The_Confidential_Password_Attributes()
    {
        Assert.DoesNotContain("msLAPS-EncryptedPassword", IA06_PamCheck.PopulationFilter);
        Assert.DoesNotContain("ms-Mcs-AdmPwd=", IA06_PamCheck.PopulationFilter);
        Assert.Contains("(!(primaryGroupID=516))", IA06_PamCheck.PopulationFilter);
        Assert.Contains("(!(primaryGroupID=521))", IA06_PamCheck.PopulationFilter);
    }

    [Fact]
    public void Access_Denied_Errors_Are_Recognized()
    {
        Assert.True(IA06_PamCheck.IsAccessDenied(new UnauthorizedAccessException()));
        Assert.True(IA06_PamCheck.IsAccessDenied(new COMException("Access is denied.", unchecked((int)0x80070005))));
        Assert.True(IA06_PamCheck.IsAccessDenied(new COMException("Insufficient access rights.", unchecked((int)0x80072098))));
        Assert.False(IA06_PamCheck.IsAccessDenied(new COMException("The server is not operational.", unchecked((int)0x8007203A))));
    }

    [Fact]
    public async Task Off_Domain_Host_Is_Not_Applicable()
    {
        var result = await new IA06_PamCheck().ExecuteAsync(new EnvironmentInfo { IsDomainJoined = false }, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.NA, result.Status);
    }

    private const string SchemaNc = "CN=Schema,CN=Configuration,DC=corp,DC=example";

    private static Task<CheckResult> Run(string fixture) =>
        new IA06_PamCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public void Snapshot_Reads_The_Schema_And_Requests_Only_Attributes_It_Defines()
    {
        var directory = FixtureDirectoryReader.Load("IA06-pass.json");

        var snapshot = IA06_PamCheck.CollectSnapshot(directory, CancellationToken.None);

        Assert.True(snapshot.WindowsLapsSchema);
        Assert.False(snapshot.LegacyLapsSchema);
        Assert.Null(snapshot.SchemaError);
        // The schema lookups bind on the domain's server; the computer search stays on the domain root.
        Assert.All(directory.Queries.Where(q => q.SearchBase?.StartsWith("CN=Schema", StringComparison.OrdinalIgnoreCase) == true),
            q => Assert.True(q.OnDomainServer));
        Assert.Equal(2, directory.Queries.Count(q => q.OnDomainServer));
        Assert.Contains(directory.Queries, q => q.SearchBase is null && !q.OnDomainServer);
        Assert.Null(snapshot.SearchError);
        Assert.Equal(20, snapshot.Computers!.Count);
        Assert.Equal(19, snapshot.Computers.Count(c => c.WindowsLaps));
        Assert.DoesNotContain(snapshot.Computers, c => c.LegacyLaps);
        // An expiration time of 0 means LAPS never set a password there.
        Assert.Contains(snapshot.Computers, c => c.DistinguishedName == "CN=WS020,OU=Workstations,DC=corp,DC=example" && !c.WindowsLaps);

        var schemaQueries = directory.Queries.Where(q => q.Filter.StartsWith("(&(objectClass=attributeSchema)", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, schemaQueries.Count);
        Assert.All(schemaQueries, q =>
        {
            Assert.Equal(SchemaNc, q.SearchBase);
            Assert.Equal(System.DirectoryServices.SearchScope.OneLevel, q.Scope);
        });
        var population = Assert.Single(directory.Queries, q => q.Filter == IA06_PamCheck.PopulationFilter);
        Assert.Null(population.SearchBase);
        Assert.Equal(new[] { "distinguishedName", IA06_PamCheck.WindowsLapsExpiration }, population.Properties);
    }

    [Fact]
    public void Snapshot_Of_A_Denied_Search_Keeps_The_Access_Denied_Flag()
    {
        var snapshot = IA06_PamCheck.CollectSnapshot(FixtureDirectoryReader.Load("IA06-denied.json"), CancellationToken.None);

        Assert.Null(snapshot.Computers);
        Assert.True(snapshot.SearchAccessDenied);
        Assert.Equal("Access is denied.", snapshot.SearchError);
        Assert.True(snapshot.WindowsLapsSchema);
    }

    [Fact]
    public void Snapshot_With_An_Unreadable_Schema_Requests_Both_Attributes()
    {
        var directory = FixtureDirectoryReader.Load("IA06-schema-unreadable.json");

        var snapshot = IA06_PamCheck.CollectSnapshot(directory, CancellationToken.None);

        Assert.Equal("The server is not operational.", snapshot.SchemaError);
        Assert.Null(snapshot.WindowsLapsSchema);
        Assert.Null(snapshot.LegacyLapsSchema);
        Assert.Collection(snapshot.Computers!,
            c => Assert.True(c.WindowsLaps && !c.LegacyLaps),
            c => Assert.True(c.LegacyLaps && !c.WindowsLaps));
        var population = Assert.Single(directory.Queries);
        Assert.Equal(new[] { "distinguishedName", IA06_PamCheck.WindowsLapsExpiration, IA06_PamCheck.LegacyLapsExpiration }, population.Properties);
    }

    [Fact]
    public async Task Fixture_Fleet_At_95_Percent_Passes()
    {
        var result = await Run("IA06-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: LAPS coverage is 95.0% (19/20).", result.Findings);
        Assert.Contains("CN=WS020,OU=Workstations,DC=corp,DC=example", result.Evidence);
    }

    [Fact]
    public async Task Fixture_Fleet_At_30_Percent_Fails()
    {
        var result = await Run("IA06-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: LAPS coverage is 30.0% (3/10, target >= 80%).", result.Findings);
        Assert.Contains("Both Windows LAPS and legacy LAPS are in use", result.Findings);
    }

    [Fact]
    public async Task Fixture_Schema_Without_Laps_Fails()
    {
        var result = await Run("IA06-noschema.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("schema has neither the Windows LAPS nor the legacy LAPS attributes", result.Findings);
    }

    [Fact]
    public async Task Fixture_Access_Denied_Search_Is_Not_Assessed()
    {
        var result = await Run("IA06-denied.json");

        Assert.Equal(CheckStatus.NotAssessed, result.Status);
        Assert.Contains("denied access to computer objects", result.Findings);
        Assert.Equal("Access is denied.", result.Error);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA06_PamCheck(_ => throw new COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

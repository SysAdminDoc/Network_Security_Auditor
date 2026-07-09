using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class ScanProfileTests
{
    [Theory]
    [InlineData(ScanProfileType.Full)]
    [InlineData(ScanProfileType.Quick)]
    [InlineData(ScanProfileType.Standard)]
    [InlineData(ScanProfileType.HIPAA)]
    [InlineData(ScanProfileType.PCI)]
    [InlineData(ScanProfileType.CMMC)]
    [InlineData(ScanProfileType.SOC2)]
    [InlineData(ScanProfileType.ISO27001)]
    [InlineData(ScanProfileType.STIG)]
    [InlineData(ScanProfileType.FedRAMP)]
    [InlineData(ScanProfileType.E8)]
    [InlineData(ScanProfileType.CyberEssentials)]
    public void Profile_Resolves_To_Valid_CheckIds(ScanProfileType profile)
    {
        var ids = ScanProfiles.Resolve(profile);
        Assert.NotEmpty(ids);

        foreach (var id in ids)
        {
            Assert.True(CheckCatalog.All.ContainsKey(id), $"Profile {profile} references unknown check ID: {id}");
        }
    }

    [Fact]
    public void Full_Profile_Contains_All_69_Checks()
    {
        var ids = ScanProfiles.Resolve(ScanProfileType.Full);
        Assert.Equal(69, ids.Length);
    }

    [Fact]
    public void Stig_Profile_Uses_Only_Prose_Readiness_Checks()
    {
        var ids = ScanProfiles.Resolve(ScanProfileType.STIG);

        Assert.Equal(new[] { "IA11", "IA12" }, ids);
    }

    [Fact]
    public void Cloud_Profile_Is_Explicitly_Disabled_Until_CSharp_Cloud_Checks_Exist()
    {
        var ids = ScanProfiles.Resolve(ScanProfileType.Cloud);

        Assert.Empty(ids);
        Assert.DoesNotContain(ids, id => CheckCatalog.All.TryGetValue(id, out var meta)
            && meta.Type is CheckType.Local or CheckType.AD);
    }

    [Fact]
    public async Task Cloud_Profile_Does_Not_Run_Local_Or_Ad_Checks()
    {
        var runner = new CheckRunner(CheckRegistry.GetAllChecks());
        var options = new AuditOptions { ScanProfile = ScanProfileType.Cloud };

        var results = await runner.RunAsync(new EnvironmentInfo { IsDomainJoined = true }, options, null, CancellationToken.None);

        Assert.Empty(results);
    }

    [Fact]
    public void Quick_Profile_Is_Subset_Of_Full()
    {
        var full = new HashSet<string>(ScanProfiles.Resolve(ScanProfileType.Full));
        var quick = ScanProfiles.Resolve(ScanProfileType.Quick);

        foreach (var id in quick)
        {
            Assert.Contains(id, full);
        }

        Assert.True(quick.Length < full.Count);
    }

    [Fact]
    public void No_Profile_Has_Duplicate_Ids()
    {
        foreach (var profile in Enum.GetValues<ScanProfileType>())
        {
            var ids = ScanProfiles.Resolve(profile);
            var distinct = ids.Distinct().ToArray();
            Assert.Equal(distinct.Length, ids.Length);
        }
    }

    [Theory]
    [InlineData(ScanProfileType.E8, "E8")]
    [InlineData(ScanProfileType.CyberEssentials, "CyberEssentials")]
    public void Framework_Profile_Membership_Matches_Framework_Mapping_Column(
        ScanProfileType profile,
        string frameworkProperty)
    {
        static string? SelectMapping(ComplianceMapping mapping, string property) => property switch
        {
            "E8" => mapping.E8,
            "CyberEssentials" => mapping.CyberEssentials,
            _ => null
        };

        var expected = FrameworkMappings.All
            .Where(kv => SelectMapping(kv.Value, frameworkProperty) is not null)
            .Select(kv => kv.Key)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var actual = ScanProfiles.Resolve(profile)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(expected, actual);
    }
}

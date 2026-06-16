using NetworkSecurityAuditor.Data;
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
}

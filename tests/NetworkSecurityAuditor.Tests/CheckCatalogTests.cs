using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CheckCatalogTests
{
    [Fact]
    public void Catalog_Contains_69_Checks()
    {
        Assert.Equal(69, CheckCatalog.All.Count);
    }

    [Fact]
    public void All_Checks_Have_Required_Fields()
    {
        foreach (var (id, meta) in CheckCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(meta.Id), $"{id} has empty Id");
            Assert.False(string.IsNullOrWhiteSpace(meta.Label), $"{id} has empty Label");
            Assert.False(string.IsNullOrWhiteSpace(meta.Category), $"{id} has empty Category");
            Assert.False(string.IsNullOrWhiteSpace(meta.Hint), $"{id} has empty Hint");
            Assert.True(meta.Weight > 0, $"{id} has zero weight");
        }
    }

    [Fact]
    public void Check_Ids_Match_Dictionary_Keys()
    {
        foreach (var (key, meta) in CheckCatalog.All)
        {
            Assert.Equal(key, meta.Id);
        }
    }

    [Theory]
    [InlineData("Identity & Access", 12)]
    [InlineData("Endpoint Security", 10)]
    [InlineData("Logging & Monitoring", 8)]
    [InlineData("Network Architecture", 7)]
    [InlineData("Network Perimeter", 10)]
    [InlineData("Backup & Recovery", 8)]
    [InlineData("Common Findings", 8)]
    [InlineData("Policies & Standards", 6)]
    public void Category_Has_Expected_Count(string category, int expected)
    {
        var count = CheckCatalog.All.Values.Count(m => m.Category == category);
        Assert.Equal(expected, count);
    }

    [Fact]
    public void All_Categories_Are_Known()
    {
        var known = new HashSet<string>
        {
            "Identity & Access", "Endpoint Security", "Logging & Monitoring",
            "Network Architecture", "Network Perimeter", "Backup & Recovery",
            "Common Findings", "Policies & Standards"
        };

        foreach (var meta in CheckCatalog.All.Values)
        {
            Assert.Contains(meta.Category, known);
        }
    }

    [Fact]
    public void Severity_Weights_Match_Enum_Values()
    {
        foreach (var meta in CheckCatalog.All.Values)
        {
            Assert.True(meta.Weight >= (int)Severity.Low && meta.Weight <= (int)Severity.Critical,
                $"{meta.Id} has weight {meta.Weight} outside valid range [{(int)Severity.Low}-{(int)Severity.Critical}]");
        }
    }
}

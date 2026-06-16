using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;

namespace NetworkSecurityAuditor.Tests;

public class CheckRegistryTests
{
    [Fact]
    public void Registry_Contains_All_Catalog_Checks()
    {
        var registry = CheckRegistry.GetAllChecks();

        foreach (var id in CheckCatalog.All.Keys)
        {
            Assert.True(registry.ContainsKey(id), $"CheckRegistry missing catalog entry: {id}");
        }
    }

    [Fact]
    public void Registry_Count_Matches_Catalog()
    {
        var registry = CheckRegistry.GetAllChecks();
        Assert.Equal(CheckCatalog.All.Count, registry.Count);
    }

    [Fact]
    public void All_Check_Ids_Match_Expected_Format()
    {
        var registry = CheckRegistry.GetAllChecks();

        foreach (var id in registry.Keys)
        {
            Assert.Matches(@"^[A-Z]{2}\d{2}$", id);
        }
    }

    [Fact]
    public void No_Null_Checks_In_Registry()
    {
        var registry = CheckRegistry.GetAllChecks();

        foreach (var (id, check) in registry)
        {
            Assert.NotNull(check);
            Assert.Equal(id, check.Id, StringComparer.OrdinalIgnoreCase);
        }
    }
}

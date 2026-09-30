using System.Reflection;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

/// <summary>Every AD check runs against recorded fixtures, so none can ship untested against the directory.</summary>
public class DirectoryCheckCoverageTests
{
    // Typed AD but read only the local registry (and adapters), so their fixtures are in-memory registries.
    private static readonly HashSet<string> RegistryOnly = new(StringComparer.OrdinalIgnoreCase) { "IA03", "IA09" };

    private static IEnumerable<string> DirectoryCheckIds() =>
        CheckCatalog.All.Where(kv => kv.Value.Type == CheckType.AD && !RegistryOnly.Contains(kv.Key)).Select(kv => kv.Key).Append("EP10");

    [Fact]
    public void Every_Directory_Check_Has_Pass_And_Fail_Fixtures()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        var fixtures = Directory.GetFiles(Path.Combine(dir!.FullName, "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Directory"), "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var id in DirectoryCheckIds())
        {
            Assert.True(fixtures.Contains($"{id}-pass"), $"{id} has no Pass fixture.");
            Assert.True(fixtures.Contains($"{id}-fail"), $"{id} has no Fail fixture.");
        }
    }

    [Fact]
    public void Every_Ad_Check_Takes_A_Reader_Seam()
    {
        var checks = CheckRegistry.GetAllChecks();
        foreach (var id in DirectoryCheckIds().Concat(RegistryOnly))
        {
            var seam = RegistryOnly.Contains(id) ? typeof(IRegistryReader) : typeof(Func<EnvironmentInfo, IDirectoryReader>);
            var ctors = checks[id].GetType().GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.True(ctors.Any(c => c.GetParameters().Any(p => p.ParameterType == seam)), $"{id} has no {seam.Name} constructor.");
        }
    }
}

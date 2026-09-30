using System.Reflection;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

/// <summary>Every AD check runs against recorded fixtures, so none can ship untested against the directory.</summary>
public class DirectoryCheckCoverageTests
{
    // Every check typed AD, which a workgroup host skips, plus EP10, which is Local but also sweeps AD computers.
    private static IEnumerable<string> DirectoryCheckIds() =>
        CheckCatalog.All.Where(kv => kv.Value.Type == CheckType.AD).Select(kv => kv.Key).Append("EP10");

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

    // A check typed AD that never reads the directory is skipped on a workgroup host for nothing, as IA03 and IA09 were.
    [Fact]
    public void Every_Ad_Check_Takes_A_Reader_Seam()
    {
        var checks = CheckRegistry.GetAllChecks();
        var seam = typeof(Func<EnvironmentInfo, IDirectoryReader>);
        foreach (var id in DirectoryCheckIds())
        {
            var ctors = checks[id].GetType().GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.True(ctors.Any(c => c.GetParameters().Any(p => p.ParameterType == seam)), $"{id} has no {seam.Name} constructor.");
        }
    }
}

using NetworkSecurityAuditor.Data;

namespace NetworkSecurityAuditor.Tests;

public class BenchmarkMetadataTests
{
    [Fact]
    public void Manifest_Has_Current_Source_Metadata_And_Known_Check_Coverage()
    {
        var manifest = LoadManifest();
        var issues = BenchmarkMetadata.Validate(
            manifest,
            CheckCatalog.All.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase),
            DateOnly.FromDateTime(DateTime.UtcNow));

        Assert.Empty(issues);
        Assert.NotNull(manifest.FindSource(BenchmarkMetadata.CisWindowsSourceId));
        Assert.NotNull(manifest.FindSource(BenchmarkMetadata.CisControlsSourceId));
        Assert.NotNull(manifest.FindSource("disa-windows-server-2025-stig"));
        Assert.NotNull(manifest.FindSource("microsoft-windows-lifecycle"));
        Assert.NotNull(manifest.FindSource("microsoft-smb-signing"));
        Assert.NotNull(manifest.FindSource("hardeningkitty-finding-list-model"));
    }

    [Fact]
    public void Cis_Catalog_Benchmark_Labels_Match_Manifest_Coverage()
    {
        var manifest = LoadManifest();
        var cisWindows = manifest.FindSource(BenchmarkMetadata.CisWindowsSourceId)
            ?? throw new InvalidDataException("CIS Windows metadata source missing.");
        var cisControls = manifest.FindSource(BenchmarkMetadata.CisControlsSourceId)
            ?? throw new InvalidDataException("CIS Controls metadata source missing.");

        var catalogWindowsIds = CheckCatalog.All.Values
            .Where(meta => meta.CisBenchmark == cisWindows.CatalogLabel)
            .Select(meta => meta.Id)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var catalogControlsIds = CheckCatalog.All.Values
            .Where(meta => meta.CisBenchmark == cisControls.CatalogLabel)
            .Select(meta => meta.Id)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(catalogWindowsIds, cisWindows.CoveredCheckIds.Order(StringComparer.OrdinalIgnoreCase).ToArray());
        Assert.Equal(catalogControlsIds, cisControls.CoveredCheckIds.Order(StringComparer.OrdinalIgnoreCase).ToArray());
        Assert.Equal(CheckCatalog.All.Count, catalogWindowsIds.Length + catalogControlsIds.Length);
    }

    [Fact]
    public void Stig_Source_Covers_Only_Prose_Backed_Stig_Checks()
    {
        var manifest = LoadManifest();
        var stig = manifest.FindSource("disa-windows-server-2025-stig")
            ?? throw new InvalidDataException("DISA STIG metadata source missing.");
        var mappedIds = FrameworkMappings.All
            .Where(kv => kv.Value.STIG is not null)
            .Select(kv => kv.Key)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(mappedIds, stig.CoveredCheckIds.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    [Fact]
    public void Validation_Fails_When_Source_Metadata_Is_Missing()
    {
        var manifest = new BenchmarkMetadataManifest
        {
            SchemaVersion = 1,
            ManifestVersion = "test",
            ReviewedOn = new DateOnly(2026, 7, 8),
            DefaultStaleAfterDays = 180,
            Sources =
            [
                new BenchmarkSourceMetadata
                {
                    Id = "missing-source-fields",
                    CoveredCheckIds = ["EP03"]
                }
            ]
        };

        var issues = BenchmarkMetadata.Validate(
            manifest,
            CheckCatalog.All.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase),
            new DateOnly(2026, 7, 8));

        Assert.Contains(issues, issue => issue.Contains("source_version", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(issues, issue => issue.Contains("source_url", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(issues, issue => issue.Contains("reviewed_on", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(issues, issue => issue.Contains("supported_os", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(issues, issue => issue.Contains("supported_builds", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validation_Fails_When_Source_Is_Stale()
    {
        var manifest = new BenchmarkMetadataManifest
        {
            SchemaVersion = 1,
            ManifestVersion = "test",
            ReviewedOn = new DateOnly(2026, 7, 8),
            DefaultStaleAfterDays = 30,
            Sources =
            [
                new BenchmarkSourceMetadata
                {
                    Id = "stale-source",
                    Name = "Stale source",
                    SourceVersion = "v1",
                    SourceUrl = "https://example.test/source",
                    ReviewedOn = new DateOnly(2026, 1, 1),
                    SupportedOs = ["Windows Server 2025"],
                    SupportedBuilds = ["10.0.26100+"],
                    CatalogLabel = "Stale source",
                    CoveredCheckIds = ["EP03"]
                }
            ]
        };

        var issues = BenchmarkMetadata.Validate(
            manifest,
            CheckCatalog.All.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase),
            new DateOnly(2026, 7, 8));

        Assert.Contains(issues, issue => issue.Contains("stale", StringComparison.OrdinalIgnoreCase));
    }

    private static BenchmarkMetadataManifest LoadManifest()
    {
        return BenchmarkMetadata.LoadFromFile(Path.Combine(
            FindRepoRoot(),
            "src",
            "NetworkSecurityAuditor",
            "Data",
            BenchmarkMetadata.ManifestFileName));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

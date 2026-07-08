using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;

namespace NetworkSecurityAuditor.Data;

public static class BenchmarkMetadata
{
    public const string ManifestFileName = "BenchmarkMetadata.json";
    public const string CisWindowsSourceId = "cis-windows-baselines-2026-03";
    public const string CisControlsSourceId = "cis-controls-v8.1";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowTrailingCommas = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
    };

    private static readonly Lazy<BenchmarkMetadataManifest> DefaultManifest = new(LoadDefaultManifest);

    public static BenchmarkMetadataManifest Default => DefaultManifest.Value;

    public static string CisWindowsCatalogLabel => RequireSource(CisWindowsSourceId).CatalogLabel;

    public static string CisControlsCatalogLabel => RequireSource(CisControlsSourceId).CatalogLabel;

    public static BenchmarkMetadataManifest LoadFromFile(string path)
    {
        using var stream = File.OpenRead(path);
        return JsonSerializer.Deserialize<BenchmarkMetadataManifest>(stream, JsonOptions)
            ?? throw new InvalidDataException($"Benchmark metadata manifest is empty: {path}");
    }

    public static BenchmarkSourceMetadata RequireSource(string sourceId)
    {
        return Default.FindSource(sourceId)
            ?? throw new InvalidDataException($"Benchmark metadata source '{sourceId}' is missing from {ManifestFileName}.");
    }

    public static IReadOnlyList<string> Validate(
        BenchmarkMetadataManifest manifest,
        IReadOnlySet<string> knownCheckIds,
        DateOnly today)
    {
        var issues = new List<string>();

        if (manifest.SchemaVersion != 1)
        {
            issues.Add("Benchmark metadata schema_version must be 1.");
        }

        if (string.IsNullOrWhiteSpace(manifest.ManifestVersion))
        {
            issues.Add("Benchmark metadata manifest_version is required.");
        }

        if (manifest.ReviewedOn == default)
        {
            issues.Add("Benchmark metadata reviewed_on is required.");
        }

        if (manifest.DefaultStaleAfterDays <= 0)
        {
            issues.Add("Benchmark metadata default_stale_after_days must be positive.");
        }

        if (manifest.Sources.Length == 0)
        {
            issues.Add("Benchmark metadata must define at least one source.");
        }

        var sourceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in manifest.Sources)
        {
            var label = string.IsNullOrWhiteSpace(source.Id) ? "<missing id>" : source.Id;

            if (string.IsNullOrWhiteSpace(source.Id))
            {
                issues.Add("Benchmark source id is required.");
            }
            else if (!sourceIds.Add(source.Id))
            {
                issues.Add($"Benchmark source '{source.Id}' is duplicated.");
            }

            if (string.IsNullOrWhiteSpace(source.Name))
            {
                issues.Add($"Benchmark source '{label}' name is required.");
            }

            if (string.IsNullOrWhiteSpace(source.SourceVersion))
            {
                issues.Add($"Benchmark source '{label}' source_version is required.");
            }

            if (!Uri.TryCreate(source.SourceUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                issues.Add($"Benchmark source '{label}' source_url must be an absolute HTTP(S) URL.");
            }

            if (source.ReviewedOn == default)
            {
                issues.Add($"Benchmark source '{label}' reviewed_on is required.");
            }
            else
            {
                var staleAfterDays = source.StaleAfterDays ?? manifest.DefaultStaleAfterDays;
                if (staleAfterDays <= 0)
                {
                    issues.Add($"Benchmark source '{label}' stale_after_days must be positive.");
                }
                else if (source.ReviewedOn.AddDays(staleAfterDays) < today)
                {
                    issues.Add($"Benchmark source '{label}' is stale; reviewed_on {source.ReviewedOn:yyyy-MM-dd} exceeds {staleAfterDays} days.");
                }
            }

            if (source.SupportedOs.Length == 0 || source.SupportedOs.Any(string.IsNullOrWhiteSpace))
            {
                issues.Add($"Benchmark source '{label}' must record supported_os.");
            }

            if (source.SupportedBuilds.Length == 0 || source.SupportedBuilds.Any(string.IsNullOrWhiteSpace))
            {
                issues.Add($"Benchmark source '{label}' must record supported_builds.");
            }

            if (string.IsNullOrWhiteSpace(source.CatalogLabel))
            {
                issues.Add($"Benchmark source '{label}' catalog_label is required.");
            }

            if (source.CoveredCheckIds.Length == 0)
            {
                issues.Add($"Benchmark source '{label}' must cover at least one check.");
            }

            var coverage = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var checkId in source.CoveredCheckIds)
            {
                if (string.IsNullOrWhiteSpace(checkId))
                {
                    issues.Add($"Benchmark source '{label}' has an empty covered_check_ids entry.");
                    continue;
                }

                if (!knownCheckIds.Contains(checkId))
                {
                    issues.Add($"Benchmark source '{label}' references unknown check '{checkId}'.");
                }

                if (!coverage.Add(checkId))
                {
                    issues.Add($"Benchmark source '{label}' duplicates check '{checkId}'.");
                }
            }
        }

        return issues;
    }

    private static BenchmarkMetadataManifest LoadDefaultManifest()
    {
        foreach (var candidate in CandidateManifestPaths())
        {
            if (File.Exists(candidate))
            {
                return LoadFromFile(candidate);
            }
        }

        throw new FileNotFoundException($"Could not locate {ManifestFileName}.");
    }

    private static IEnumerable<string> CandidateManifestPaths()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "Data", ManifestFileName);
        yield return Path.Combine(AppContext.BaseDirectory, ManifestFileName);

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            yield return Path.Combine(dir.FullName, "src", "NetworkSecurityAuditor", "Data", ManifestFileName);
            dir = dir.Parent;
        }
    }
}

public sealed class BenchmarkMetadataManifest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("manifest_version")]
    public string ManifestVersion { get; init; } = string.Empty;

    [JsonPropertyName("reviewed_on")]
    public DateOnly ReviewedOn { get; init; }

    [JsonPropertyName("default_stale_after_days")]
    public int DefaultStaleAfterDays { get; init; }

    [JsonPropertyName("sources")]
    public BenchmarkSourceMetadata[] Sources { get; init; } = [];

    public BenchmarkSourceMetadata? FindSource(string sourceId) =>
        Sources.FirstOrDefault(source => source.Id.Equals(sourceId, StringComparison.OrdinalIgnoreCase));
}

public sealed class BenchmarkSourceMetadata
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("source_version")]
    public string SourceVersion { get; init; } = string.Empty;

    [JsonPropertyName("source_url")]
    public string SourceUrl { get; init; } = string.Empty;

    [JsonPropertyName("reviewed_on")]
    public DateOnly ReviewedOn { get; init; }

    [JsonPropertyName("stale_after_days")]
    public int? StaleAfterDays { get; init; }

    [JsonPropertyName("supported_os")]
    public string[] SupportedOs { get; init; } = [];

    [JsonPropertyName("supported_builds")]
    public string[] SupportedBuilds { get; init; } = [];

    [JsonPropertyName("catalog_label")]
    public string CatalogLabel { get; init; } = string.Empty;

    [JsonPropertyName("covered_check_ids")]
    public string[] CoveredCheckIds { get; init; } = [];
}

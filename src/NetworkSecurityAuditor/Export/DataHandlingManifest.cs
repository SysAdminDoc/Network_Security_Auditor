using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSecurityAuditor.Export;

public sealed class DataHandlingManifest
{
    public string SchemaVersion { get; init; } = "1.0";
    public string PolicyVersion { get; init; } = "1.0";
    public string GeneratedAtUtc { get; init; } = DateTime.UtcNow.ToString("O");
    public bool PrivacyMode { get; init; }
    public string IdentityStrategy { get; init; } = "present";
    public string SourcePathPolicy { get; init; } = "included only where required by the export format";
    public IReadOnlyDictionary<string, string> FieldClassifications { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<string> SecretFieldsExcluded { get; init; } = [];
    public IReadOnlyList<string> Artifacts { get; init; } = [];
    public IReadOnlyDictionary<string, string> Redaction { get; init; } = new Dictionary<string, string>();
}

public static class DataHandlingManifestWriter
{
    public const string PolicyVersion = "1.0";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static DataHandlingManifest Create(bool privacyMode, IEnumerable<string> artifactPaths)
    {
        var artifacts = artifactPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => Path.GetFileName(path) ?? string.Empty)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var identityState = privacyMode ? "pseudonymized" : "present";
        return new DataHandlingManifest
        {
            PolicyVersion = PolicyVersion,
            PrivacyMode = privacyMode,
            IdentityStrategy = privacyMode ? "sha256-pseudonym" : "present",
            SourcePathPolicy = privacyMode ? "redacted" : "included only where required by the export format",
            FieldClassifications = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["identity"] = "tenant-sensitive",
                ["host_and_domain"] = "tenant-sensitive",
                ["findings_and_evidence"] = "technical-sensitive",
                ["source_paths"] = "restricted",
                ["credentials_and_tokens"] = "secret-excluded",
                ["scores_and_status"] = "operational"
            },
            SecretFieldsExcluded = ["access_token", "refresh_token", "client_secret", "password", "private_key", "authorization"],
            Artifacts = artifacts,
            Redaction = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["hostnames"] = identityState,
                ["domains"] = identityState,
                ["tenant_and_user_identifiers"] = identityState,
                ["secrets"] = "removed"
            }
        };
    }

    public static string SidecarPath(string artifactPath) => $"{artifactPath}.data-handling.json";

    public static Task WriteAsync(string path, bool privacyMode, IEnumerable<string> artifactPaths)
    {
        var json = JsonSerializer.Serialize(Create(privacyMode, artifactPaths), JsonOptions);
        return Services.AtomicFileWriter.WriteAllTextAsync(path, json);
    }
}

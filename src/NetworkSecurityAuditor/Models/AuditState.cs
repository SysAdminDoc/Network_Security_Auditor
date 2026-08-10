using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Models;

public sealed class AuditState
{
    public const string CurrentSchemaVersion = "1.0";
    public const long MaxImportBytes = ImportFileGuard.MaxAuditStateBytes;

    public string SchemaVersion { get; set; } = CurrentSchemaVersion;
    public string ToolVersion { get; set; } = VersionInfo.Version;
    public string Client { get; set; } = "";
    public string Auditor { get; set; } = "";
    public DateTime SavedAt { get; set; } = DateTime.UtcNow;
    public string ScanProfile { get; set; } = "";
    public string Theme { get; set; } = "";
    public int OverallScore { get; set; }
    public string Grade { get; set; } = "";
    public int RansomwareScore { get; set; }
    public string RansomwareGrade { get; set; } = "";
    public int DomainMaturityScore { get; set; }
    public string DomainMaturityGrade { get; set; } = "";
    public List<CheckState> Checks { get; set; } = [];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public string Serialize() => JsonSerializer.Serialize(this, SerializerOptions);

    public static AuditState? Deserialize(string json)
        => JsonSerializer.Deserialize<AuditState>(json, SerializerOptions);

    public static async Task<AuditState?> LoadFromFileAsync(string path)
    {
        if (!File.Exists(path))
            return null;

        ImportFileGuard.EnsureWithinSizeLimit(path, MaxImportBytes, "Audit state");
        var json = await File.ReadAllTextAsync(path);
        return Deserialize(json);
    }
}

public sealed class CheckState
{
    public string Id { get; set; } = "";
    public CheckStatus Status { get; set; }
    public string Findings { get; set; } = "";
    public string Evidence { get; set; } = "";
    public string Notes { get; set; } = "";
    public string RemediationAssignee { get; set; } = "";
    public string? RemediationDueDate { get; set; }
}

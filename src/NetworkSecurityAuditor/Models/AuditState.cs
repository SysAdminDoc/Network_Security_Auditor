using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Models;

public sealed class AuditState
{
    public const string CurrentSchemaVersion = "1.1";
    public const long MaxImportBytes = ImportFileGuard.MaxAuditStateBytes;

    /// <summary>Schema versions this build loads. 1.0 (v5.4.0) is migrated on load.</summary>
    public static readonly IReadOnlyList<string> SupportedSchemaVersions = ["1.0", CurrentSchemaVersion];

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

    /// <summary>
    /// Brings a 1.0 state (v5.4.0) up to the current schema and returns how many checks changed.
    /// Errors and timeouts were saved as NA and become Error. Questionnaire checks were saved with the
    /// scan's automatic Partial; one with no operator note is taken as unanswered and becomes NotAssessed.
    /// </summary>
    public int MigrateToCurrent()
    {
        if (string.Equals(SchemaVersion, CurrentSchemaVersion, StringComparison.OrdinalIgnoreCase))
            return 0;

        var changed = 0;
        foreach (var check in Checks)
        {
            if (check.Status == CheckStatus.NA &&
                (CheckResult.IsErrorEvidence(check.Evidence) || CheckResult.IsTimeoutEvidence(check.Evidence)))
            {
                check.Status = CheckStatus.Error;
                changed++;
            }
            else if (check.Status == CheckStatus.Partial &&
                Data.CheckCatalog.QuestionnaireIds.Contains(check.Id) &&
                string.IsNullOrWhiteSpace(check.Notes))
            {
                check.Status = CheckStatus.NotAssessed;
                changed++;
            }
        }

        SchemaVersion = CurrentSchemaVersion;
        return changed;
    }

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

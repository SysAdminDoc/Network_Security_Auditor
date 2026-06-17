using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSecurityAuditor.Models;

public sealed class AuditState
{
    public string SchemaVersion { get; set; } = "1.0";
    public string ToolVersion { get; set; } = "5.0.0";
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

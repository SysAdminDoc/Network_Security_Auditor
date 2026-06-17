namespace NetworkSecurityAuditor.Models;

public sealed class CheckMetadata
{
    public required string Id { get; init; }
    public required string Category { get; init; }
    public required string Label { get; init; }
    public required string Hint { get; init; }
    public required Severity Severity { get; init; }
    public required int Weight { get; init; }
    public required CheckType Type { get; init; }
    public required RiskTier RiskTier { get; init; }
    public required string Compliance { get; init; }
    public EvidenceMode EvidenceMode { get; init; } = EvidenceMode.Automated;
    public string? RemediationUrl { get; init; }
}

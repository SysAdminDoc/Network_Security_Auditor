using CommunityToolkit.Mvvm.ComponentModel;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.ViewModels;

public partial class CheckItemViewModel : ViewModelBase
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public required string Category { get; init; }
    public required Severity Severity { get; init; }
    public int Weight { get; init; } = 1;
    public string Compliance { get; init; } = "";
    public string? RemediationUrl { get; init; }
    public EvidenceMode EvidenceMode { get; init; }
    public RiskTier RiskTier { get; init; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusColor))]
    private CheckStatus _status = CheckStatus.NotAssessed;

    [ObservableProperty]
    private string _findings = "";

    [ObservableProperty]
    private string _evidence = "";

    [ObservableProperty]
    private string _notes = "";

    [ObservableProperty]
    private string _remediationAssignee = "";

    [ObservableProperty]
    private DateTime? _remediationDueDate;

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private double _durationMs;

    public string StatusColor => Status switch
    {
        CheckStatus.Pass => "#a6e3a1",
        CheckStatus.Partial => "#f9e2af",
        CheckStatus.Fail => "#f38ba8",
        CheckStatus.NA => "#9399b2",
        CheckStatus.NotAssessed => "#585b70",
        _ => "#585b70"
    };

    public string SeverityLabel => Severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "UNKNOWN"
    };

    public string SeverityColor => Severity switch
    {
        Severity.Critical => "#f38ba8",
        Severity.High => "#fab387",
        Severity.Medium => "#f9e2af",
        Severity.Low => "#a6e3a1",
        _ => "#9399b2"
    };

    public static CheckItemViewModel FromMetadata(CheckMetadata meta) => new()
    {
        Id = meta.Id,
        Label = meta.Label,
        Category = meta.Category,
        Severity = meta.Severity,
        Weight = meta.Weight,
        Compliance = meta.Compliance,
        RemediationUrl = meta.RemediationUrl,
        EvidenceMode = meta.EvidenceMode,
        RiskTier = meta.RiskTier
    };
}

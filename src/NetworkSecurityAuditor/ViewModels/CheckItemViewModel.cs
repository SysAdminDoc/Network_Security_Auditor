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
    [NotifyPropertyChangedFor(nameof(StatusBrushKey))]
    [NotifyPropertyChangedFor(nameof(StatusForegroundBrushKey))]
    [NotifyPropertyChangedFor(nameof(StatusLabel))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
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
    [NotifyPropertyChangedFor(nameof(DurationDisplay))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private double _durationMs;

    public string StatusLabel => Status switch
    {
        CheckStatus.NotAssessed => "Not assessed",
        CheckStatus.NA => "N/A",
        _ => Status.ToString()
    };

    public string DurationDisplay => DurationMs > 0
        ? $"{DurationMs:0} ms"
        : "--";

    public string AccessibilitySummary =>
        $"{Id}. {SeverityLabel.ToLowerInvariant()} severity. {Label}. Category {Category}. Status {StatusLabel.ToLowerInvariant()}. Runtime {(DurationMs > 0 ? DurationDisplay : "not run")}.";

    public string StatusBrushKey => Status switch
    {
        CheckStatus.Pass => "ProgressGood",
        CheckStatus.Partial => "ProgressMid",
        CheckStatus.Fail => "ProgressBad",
        CheckStatus.NA => "StatusNeutral",
        CheckStatus.NotAssessed => "BadgeBg",
        _ => "BadgeBg"
    };

    public string StatusForegroundBrushKey => Status == CheckStatus.NotAssessed
        ? "TextSecondary"
        : "WindowBg";

    public string SeverityLabel => Severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "UNKNOWN"
    };

    public string SeverityBrushKey => Severity switch
    {
        Severity.Critical => "ProgressBad",
        Severity.High => "SeverityHigh",
        Severity.Medium => "ProgressMid",
        Severity.Low => "ProgressGood",
        _ => "StatusNeutral"
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

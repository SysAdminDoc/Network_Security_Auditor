using CommunityToolkit.Mvvm.ComponentModel;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.ViewModels;

public sealed partial class CategorySummaryViewModel : ViewModelBase
{
    public required string Name { get; init; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScoreDisplay))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _score;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _total;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _passCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _partialCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _failCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _notApplicableCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(CompletedCount))]
    [NotifyPropertyChangedFor(nameof(CompletionDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthLabel))]
    [NotifyPropertyChangedFor(nameof(AccessibilitySummary))]
    private int _notAssessedCount;

    public int AssessedCount => PassCount + PartialCount + FailCount;

    public int CompletedCount => AssessedCount + NotApplicableCount;

    public string ScoreDisplay => AssessedCount > 0 ? $"{Score}%" : "--";

    public string AssessedDisplay => $"{CompletedCount}/{Total}";

    public string CompletionDisplay => $"{CompletedCount} of {Total} completed";

    public string HealthBrushKey => AssessedCount == 0
        ? "StatusNeutral"
        : FailCount > 0
            ? "ProgressBad"
            : PartialCount > 0
                ? "ProgressMid"
                : "ProgressGood";

    public string HealthLabel => Total > 0 && NotApplicableCount == Total
        ? "Not applicable"
        : CompletedCount == 0
            ? "Open"
            : CompletedCount < Total
                ? "In progress"
                : FailCount > 0
                    ? "Review"
                    : PartialCount > 0
                        ? "Partial"
                        : "Clear";

    public string AccessibilitySummary =>
        $"{Name}. {CompletionDisplay}. {HealthLabel}. {(AssessedCount > 0 ? $"Score {Score} percent" : "Score not available")}.";

    public void Update(IEnumerable<CheckItemViewModel> checks)
    {
        var categoryChecks = Name.Equals("All", StringComparison.OrdinalIgnoreCase)
            ? checks.ToList()
            : checks
                .Where(c => c.Category.Equals(Name, StringComparison.OrdinalIgnoreCase))
                .ToList();

        Total = categoryChecks.Count;
        PassCount = categoryChecks.Count(c => c.Status == CheckStatus.Pass);
        PartialCount = categoryChecks.Count(c => c.Status == CheckStatus.Partial);
        FailCount = categoryChecks.Count(c => c.Status == CheckStatus.Fail);
        NotApplicableCount = categoryChecks.Count(c => c.Status == CheckStatus.NA);
        NotAssessedCount = categoryChecks.Count(c => c.Status == CheckStatus.NotAssessed);

        var possible = categoryChecks
            .Where(c => c.Status is CheckStatus.Pass or CheckStatus.Partial or CheckStatus.Fail)
            .Sum(c => c.Weight);

        if (possible <= 0)
        {
            Score = 0;
            return;
        }

        var earned = categoryChecks.Sum(c => c.Status switch
        {
            CheckStatus.Pass => c.Weight,
            CheckStatus.Partial => c.Weight / 2.0,
            _ => 0
        });

        Score = (int)Math.Round(earned / possible * 100, MidpointRounding.AwayFromZero);
        OnPropertyChanged(nameof(HealthLabel));
    }
}

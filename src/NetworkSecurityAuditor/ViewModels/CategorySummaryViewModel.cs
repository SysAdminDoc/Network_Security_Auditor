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
    private int _score;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    private int _total;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    private int _passCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    private int _partialCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount))]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    [NotifyPropertyChangedFor(nameof(HealthBrushKey))]
    private int _failCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    private int _notApplicableCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedDisplay))]
    private int _notAssessedCount;

    public int AssessedCount => PassCount + PartialCount + FailCount;

    public string ScoreDisplay => AssessedCount > 0 ? $"{Score}%" : "--";

    public string AssessedDisplay => $"{AssessedCount}/{Total}";

    public string HealthBrushKey => AssessedCount == 0
        ? "StatusNeutral"
        : FailCount > 0
            ? "ProgressBad"
            : PartialCount > 0
                ? "ProgressMid"
                : "ProgressGood";

    public void Update(IEnumerable<CheckItemViewModel> checks)
    {
        var categoryChecks = checks
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
    }
}

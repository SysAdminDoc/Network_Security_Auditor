using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public sealed class AccessibilityViewModelTests
{
    [Fact]
    public void Check_Summary_Uses_Human_Readable_Content_And_Tracks_State()
    {
        var check = new CheckItemViewModel
        {
            Id = "BR01",
            Label = "Backup solution",
            Category = "Backup and Recovery",
            Severity = Severity.Critical
        };

        Assert.Contains("BR01. critical severity. Backup solution.", check.AccessibilitySummary);
        Assert.Contains("Status not assessed. Runtime not run.", check.AccessibilitySummary);

        check.Status = CheckStatus.Fail;
        check.DurationMs = 125;

        Assert.Contains("Status fail. Runtime 125 ms.", check.AccessibilitySummary);
    }

    [Fact]
    public void Category_Summary_Does_Not_Claim_Clear_Until_Every_Check_Is_Complete()
    {
        var summary = new CategorySummaryViewModel { Name = "Backup and Recovery" };
        var checks = new[]
        {
            CreateCheck("BR01", CheckStatus.Pass),
            CreateCheck("BR02", CheckStatus.NotAssessed)
        };

        summary.Update(checks);

        Assert.Equal("1/2", summary.AssessedDisplay);
        Assert.Equal("In progress", summary.HealthLabel);
        Assert.Contains("1 of 2 completed", summary.AccessibilitySummary);
    }

    [Fact]
    public void Category_Summary_Treats_Not_Applicable_As_Completed_Without_A_Score()
    {
        var summary = new CategorySummaryViewModel { Name = "Backup and Recovery" };

        summary.Update(new[]
        {
            CreateCheck("BR01", CheckStatus.NA),
            CreateCheck("BR02", CheckStatus.NA)
        });

        Assert.Equal("2/2", summary.AssessedDisplay);
        Assert.Equal("Not applicable", summary.HealthLabel);
        Assert.Equal("--", summary.ScoreDisplay);
        Assert.Contains("Score not available", summary.AccessibilitySummary);
    }

    private static CheckItemViewModel CreateCheck(string id, CheckStatus status) => new()
    {
        Id = id,
        Label = id,
        Category = "Backup and Recovery",
        Severity = Severity.Medium,
        Status = status
    };
}

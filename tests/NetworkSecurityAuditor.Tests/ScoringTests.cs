using System.Collections.ObjectModel;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.ViewModels;
using NetworkSecurityAuditor.Data;

namespace NetworkSecurityAuditor.Tests;

public class ScoringTests
{
    private static ObservableCollection<CheckItemViewModel> CreateChecks(params (string id, CheckStatus status)[] items)
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var (id, status) in items)
        {
            if (CheckCatalog.All.TryGetValue(id, out var meta))
            {
                var vm = CheckItemViewModel.FromMetadata(meta);
                vm.Status = status;
                checks.Add(vm);
            }
        }
        return checks;
    }

    [Fact]
    public void All_Pass_Returns_100()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Pass),
            ("EP02", CheckStatus.Pass),
            ("EP03", CheckStatus.Pass));

        var (score, grade) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }

    [Fact]
    public void All_Fail_Returns_0()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Fail),
            ("EP02", CheckStatus.Fail),
            ("EP03", CheckStatus.Fail));

        var (score, _) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(0, score);
    }

    [Fact]
    public void NA_Checks_Excluded_From_Score()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Pass),
            ("EP02", CheckStatus.NA));

        var (score, _) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(100, score);
    }

    [Fact]
    public void NotAssessed_Excluded_From_Score()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Pass),
            ("EP02", CheckStatus.NotAssessed));

        var (score, _) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(100, score);
    }

    [Fact]
    public void Partial_Gets_Half_Credit()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Partial),
            ("EP02", CheckStatus.Partial));

        var (score, _) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(50, score);
    }

    [Fact]
    public void Uses_Check_Weight_Without_Severity_Squaring()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Pass),
            ("EP02", CheckStatus.Fail));

        var (score, _) = RiskScoreEngine.Calculate(checks);

        Assert.Equal(59, score);
    }

    [Fact]
    public void Normalizes_Per_Category_Before_Applying_Category_Weights()
    {
        var checks = CreateChecks(
            ("IA01", CheckStatus.Fail),
            ("EP01", CheckStatus.Pass),
            ("EP02", CheckStatus.Pass));

        var (score, _) = RiskScoreEngine.Calculate(checks);

        Assert.Equal(44, score);
    }

    [Fact]
    public void RiskScore_Rounds_Midpoints_Away_From_Zero()
    {
        var checks = new ObservableCollection<CheckItemViewModel>
        {
            new()
            {
                Id = "ROUND1",
                Label = "Round pass",
                Category = "Rounding",
                Severity = Severity.Low,
                Weight = 177,
                RiskTier = RiskTier.ReadOnly,
                EvidenceMode = EvidenceMode.Automated,
                Status = CheckStatus.Pass
            },
            new()
            {
                Id = "ROUND2",
                Label = "Round fail",
                Category = "Rounding",
                Severity = Severity.Low,
                Weight = 23,
                RiskTier = RiskTier.ReadOnly,
                EvidenceMode = EvidenceMode.Automated,
                Status = CheckStatus.Fail
            }
        };

        var (score, _) = RiskScoreEngine.Calculate(checks);

        Assert.Equal(89, score);
    }

    [Fact]
    public void Scoring_Engines_Use_AwayFromZero_Rounding()
    {
        var root = FindRepoRoot();
        var files = new[]
        {
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Scoring", "RiskScoreEngine.cs"),
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Scoring", "RansomwareReadinessEngine.cs"),
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Scoring", "DomainMaturityEngine.cs")
        };

        foreach (var file in files)
        {
            var source = File.ReadAllText(file);
            Assert.Contains("MidpointRounding.AwayFromZero", source);
        }
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(85, "B")]
    [InlineData(80, "B")]
    [InlineData(75, "C")]
    [InlineData(70, "C")]
    [InlineData(65, "D")]
    [InlineData(60, "D")]
    [InlineData(55, "F")]
    [InlineData(0, "F")]
    public void Grade_Thresholds_Correct(int score, string expectedGrade)
    {
        Assert.Equal(expectedGrade, RiskScoreEngine.GradeFromScore(score));
    }

    [Fact]
    public void Ransomware_Engine_Returns_Valid_Score()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.Pass),
            ("EP07", CheckStatus.Pass),
            ("NP05", CheckStatus.Fail),
            ("LM02", CheckStatus.Pass),
            ("BR01", CheckStatus.Pass));

        var (score, grade) = RansomwareReadinessEngine.Calculate(checks);
        Assert.InRange(score, 0, 100);
        Assert.Contains(grade, new[] { "A", "B", "C", "D", "F" });
    }

    [Fact]
    public void Sprs_Treats_Partial_As_Unmet()
    {
        var partialChecks = CreateChecks(("IA01", CheckStatus.Partial));
        var failChecks = CreateChecks(("IA01", CheckStatus.Fail));

        var (partialScore, _) = SprsScoreEngine.Calculate(partialChecks);
        var (failScore, _) = SprsScoreEngine.Calculate(failChecks);

        Assert.Equal(failScore, partialScore);
        Assert.Equal(95, partialScore);
    }

    [Fact]
    public void Empty_Checks_Returns_Zero()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        var (score, grade) = RiskScoreEngine.Calculate(checks);
        Assert.Equal(0, score);
        Assert.Equal("N/A", grade);
    }

    [Fact]
    public void All_NA_Checks_Return_NoData_Grade()
    {
        var checks = CreateChecks(
            ("EP01", CheckStatus.NA),
            ("EP02", CheckStatus.NotAssessed));

        var (score, grade) = RiskScoreEngine.Calculate(checks);

        Assert.Equal(0, score);
        Assert.Equal("N/A", grade);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

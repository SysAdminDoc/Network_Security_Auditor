using System.Collections.ObjectModel;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class DomainMaturityTests
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
    public void All_Pass_Returns_High_Score()
    {
        var checks = CreateChecks(
            ("IA01", CheckStatus.Pass), ("IA02", CheckStatus.Pass), ("IA06", CheckStatus.Pass),
            ("IA11", CheckStatus.Pass), ("IA12", CheckStatus.Pass), ("CF01", CheckStatus.Pass),
            ("IA04", CheckStatus.Pass), ("IA05", CheckStatus.Pass), ("IA07", CheckStatus.Pass),
            ("IA08", CheckStatus.Pass), ("IA10", CheckStatus.Pass), ("CF04", CheckStatus.Pass),
            ("EP03", CheckStatus.Pass), ("EP08", CheckStatus.Pass), ("EP04", CheckStatus.Pass),
            ("EP02", CheckStatus.Pass), ("EP05", CheckStatus.Pass),
            ("LM02", CheckStatus.Pass), ("LM03", CheckStatus.Pass), ("LM05", CheckStatus.Pass),
            ("LM08", CheckStatus.Pass));

        var (score, grade, domainScores) = DomainMaturityEngine.Calculate(checks);
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
        Assert.Equal(4, domainScores.Length);
    }

    [Fact]
    public void All_Fail_Returns_Zero()
    {
        var checks = CreateChecks(
            ("IA01", CheckStatus.Fail), ("IA02", CheckStatus.Fail),
            ("EP03", CheckStatus.Fail), ("LM02", CheckStatus.Fail));

        var (score, _, _) = DomainMaturityEngine.Calculate(checks);
        Assert.Equal(0, score);
    }

    [Fact]
    public void Empty_Checks_Returns_Zero()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        var (score, _, domainScores) = DomainMaturityEngine.Calculate(checks);
        Assert.Equal(0, score);
        Assert.Equal(4, domainScores.Length);
    }

    [Fact]
    public void Returns_Four_Domain_Scores()
    {
        var checks = CreateChecks(("IA01", CheckStatus.Pass));
        var (_, _, domainScores) = DomainMaturityEngine.Calculate(checks);
        Assert.Equal(4, domainScores.Length);
    }

    [Fact]
    public void NA_Checks_Excluded()
    {
        var checks = CreateChecks(
            ("IA01", CheckStatus.Pass), ("IA02", CheckStatus.NA));

        var (score, _, _) = DomainMaturityEngine.Calculate(checks);
        Assert.True(score > 0);
    }

    [Fact]
    public void Domain_Names_Are_Defined()
    {
        Assert.Equal(4, DomainMaturityEngine.DomainNames.Length);
        Assert.Contains("Privileged Access", DomainMaturityEngine.DomainNames);
        Assert.Contains("Identity Hygiene", DomainMaturityEngine.DomainNames);
        Assert.Contains("Infrastructure Hardening", DomainMaturityEngine.DomainNames);
        Assert.Contains("Visibility", DomainMaturityEngine.DomainNames);
    }
}

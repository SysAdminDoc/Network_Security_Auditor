using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class PreflightCheckerTests
{
    [Fact]
    public void Run_NonAdmin_ProducesWarning()
    {
        var env = new EnvironmentInfo { IsAdmin = false };
        var results = PreflightChecker.Run(env);
        var admin = results.First(r => r.Name == "Administrator Elevation");
        Assert.False(admin.Passed);
        Assert.Contains("Not elevated", admin.Detail);
    }

    [Fact]
    public void Run_Admin_Passes()
    {
        var env = new EnvironmentInfo { IsAdmin = true };
        var results = PreflightChecker.Run(env);
        var admin = results.First(r => r.Name == "Administrator Elevation");
        Assert.True(admin.Passed);
    }

    [Fact]
    public void Run_NonDomain_ProducesWarning()
    {
        var env = new EnvironmentInfo { IsDomainJoined = false };
        var results = PreflightChecker.Run(env);
        var domain = results.First(r => r.Name == "Domain Membership");
        Assert.False(domain.Passed);
        Assert.Contains("Not domain-joined", domain.Detail);
    }

    [Fact]
    public void Run_DomainJoined_ShowsDomainName()
    {
        var env = new EnvironmentInfo { IsDomainJoined = true, DomainName = "CORP.LOCAL", JoinType = "AD" };
        var results = PreflightChecker.Run(env);
        var domain = results.First(r => r.Name == "Domain Membership");
        Assert.True(domain.Passed);
        Assert.Contains("CORP.LOCAL", domain.Detail);
    }

    [Fact]
    public void Run_Returns_Seven_Results()
    {
        var env = new EnvironmentInfo();
        var results = PreflightChecker.Run(env);
        Assert.Equal(7, results.Count);
    }

    [Fact]
    public void Run_AllResults_HaveNames()
    {
        var env = new EnvironmentInfo();
        var results = PreflightChecker.Run(env);
        Assert.All(results, r => Assert.False(string.IsNullOrEmpty(r.Name)));
    }

    [Fact]
    public void Run_AllResults_HaveDetails()
    {
        var env = new EnvironmentInfo();
        var results = PreflightChecker.Run(env);
        Assert.All(results, r => Assert.False(string.IsNullOrEmpty(r.Detail)));
    }
}

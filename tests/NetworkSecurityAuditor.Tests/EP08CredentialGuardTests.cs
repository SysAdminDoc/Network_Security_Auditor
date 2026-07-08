namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;

public sealed class EP08CredentialGuardTests
{
    [Fact]
    public void AssessSecureBoot_Treats_Unknown_As_Not_Applicable()
    {
        var assessment = EP08_CredentialGuardCheck.AssessSecureBoot(-1);

        Assert.False(assessment.IsApplicable);
        Assert.False(assessment.HasFailure);
    }

    [Fact]
    public void DetermineStatus_Returns_NA_When_No_Controls_Are_Applicable()
    {
        var status = EP08_CredentialGuardCheck.DetermineStatus(failCount: 0, totalChecks: 0);

        Assert.Equal(CheckStatus.NA, status);
    }

    [Fact]
    public void DetermineStatus_Still_Fails_When_All_Applicable_Controls_Fail()
    {
        var status = EP08_CredentialGuardCheck.DetermineStatus(failCount: 2, totalChecks: 2);

        Assert.Equal(CheckStatus.Fail, status);
    }
}

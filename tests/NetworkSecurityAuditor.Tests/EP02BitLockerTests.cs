namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;

public sealed class EP02BitLockerTests
{
    [Fact]
    public void DetermineStatus_Returns_NA_When_BitLocker_Wmi_Is_Unavailable_Without_Confirmed_Issues()
    {
        var status = EP02_BitLockerCheck.DetermineStatus(
            hasIssue: false,
            anyDriveEncrypted: false,
            bitLockerUnavailable: true);

        Assert.Equal(CheckStatus.NA, status);
    }

    [Fact]
    public void DetermineStatus_Still_Fails_When_A_Confirmed_Issue_Exists()
    {
        var status = EP02_BitLockerCheck.DetermineStatus(
            hasIssue: true,
            anyDriveEncrypted: false,
            bitLockerUnavailable: true);

        Assert.Equal(CheckStatus.Fail, status);
    }
}

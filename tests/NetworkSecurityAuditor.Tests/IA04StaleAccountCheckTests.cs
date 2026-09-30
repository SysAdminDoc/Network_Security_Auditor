using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA04StaleAccountCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new IA04_StaleAccountCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task No_Stale_Accounts_Passes()
    {
        var result = await Run("IA04-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Stale accounts (enabled, no logon in >90 days): 0", result.Findings);
    }

    [Fact]
    public async Task Stale_Unprivileged_Account_Is_Partial()
    {
        var result = await Run("IA04-partial.json");

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("j.doe | LastLogon=", result.Findings);
        Assert.DoesNotContain("PRIVILEGED", result.Findings);
    }

    [Fact]
    public async Task Stale_Domain_Admin_Fails_And_Lists_Oldest_First()
    {
        var result = await Run("IA04-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("CRITICAL: 1 stale account(s) have privileged group membership.", result.Findings);
        Assert.Contains("old.admin | LastLogon=", result.Findings);
        Assert.Contains("[PRIVILEGED: Domain Admins]", result.Findings);
        Assert.True(result.Findings.IndexOf("old.admin", StringComparison.Ordinal) < result.Findings.IndexOf("j.doe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA04_StaleAccountCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

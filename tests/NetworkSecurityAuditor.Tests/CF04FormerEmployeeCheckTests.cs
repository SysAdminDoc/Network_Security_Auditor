using System.Runtime.InteropServices;
using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CF04FormerEmployeeCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new CF04_FormerEmployeeCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Few_Unprivileged_Stale_Accounts_Pass()
    {
        var result = await Run("CF04-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Stale account analysis: 3 enabled accounts with no logon in >90 days, 0 in privileged groups.", result.Findings);
        Assert.DoesNotContain("CRITICAL", result.Findings);
        Assert.Contains("Total stale enabled accounts: 3", result.Evidence);
    }

    [Fact]
    public async Task More_Than_Twenty_Unprivileged_Stale_Accounts_Is_Partial()
    {
        var result = await Run("CF04-partial.json");

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Stale account analysis: 24 enabled accounts with no logon in >90 days, 0 in privileged groups.", result.Findings);
        Assert.DoesNotContain("WARNING", result.Findings);
        Assert.DoesNotContain("INFO:", result.Findings);
    }

    [Fact]
    public async Task Stale_Privileged_Accounts_Fail()
    {
        var result = await Run("CF04-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Stale account analysis: 3 enabled accounts with no logon in >90 days, 2 in privileged groups.", result.Findings);
        Assert.Contains("CRITICAL: \"old.admin\" - no logon in >90 days, member of Domain Admins.", result.Findings);
        Assert.Contains("CRITICAL: \"rdp.contractor\" - no logon in >90 days, member of Remote Desktop Users.", result.Findings);
        Assert.Contains("WARNING: 2 stale account(s) retain privileged access.", result.Findings);
        Assert.DoesNotContain("j.doe", result.Findings);
        Assert.Contains("STALE PRIVILEGED: rdp.contractor | Group: Remote Desktop Users | LastLogon: Never", result.Evidence);
        Assert.Matches(@"STALE PRIVILEGED: old\.admin \| Group: Domain Admins \| LastLogon: \d{4}-\d{2}-\d{2}", result.Evidence);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new CF04_FormerEmployeeCheck(_ => throw new COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

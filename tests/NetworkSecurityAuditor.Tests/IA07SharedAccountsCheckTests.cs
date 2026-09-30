using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA07SharedAccountsCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader) =>
        new IA07_SharedAccountsCheck(_ => reader)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Only_Disabled_Matches_Pass()
    {
        var reader = FixtureDirectoryReader.Load("IA07-pass.json");
        var result = await Run(reader);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Shared/generic accounts found: 2", result.Findings);
        Assert.DoesNotContain("Enabled shared accounts", result.Findings);
        Assert.Contains("Administrator | Enabled=False | PwdAge=700d | LastLogon=", result.Evidence);
        Assert.Equal(9, reader.Queries.Count);
    }

    [Fact]
    public async Task No_Matches_Pass()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA07-pass-none.json"));

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("No shared/generic accounts detected matching common naming patterns.", result.Findings);
    }

    [Fact]
    public async Task Enabled_Shared_Accounts_Fail_And_Overlapping_Matches_Count_Once()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA07-fail.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Shared/generic accounts found: 4", result.Findings);
        Assert.Contains("Enabled shared accounts: 3", result.Findings);
        Assert.Contains("Enabled with password > 180 days old: 2", result.Findings);
        Assert.Contains("scanner | Enabled=True | PwdAge=1000d | LastLogon=Never | Match=scanner", result.Evidence);
        Assert.Contains("temp.admin | Enabled=False | PwdAge=250d", result.Evidence);
        Assert.DoesNotContain("Match=temp", result.Evidence);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA07_SharedAccountsCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

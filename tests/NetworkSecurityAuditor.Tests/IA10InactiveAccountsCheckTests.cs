using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA10InactiveAccountsCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new IA10_InactiveAccountsCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task No_Inactive_Accounts_Passes()
    {
        var result = await Run("IA10-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Total inactive accounts: 0", result.Findings);
        Assert.DoesNotContain("most inactive", result.Findings);
    }

    [Fact]
    public async Task A_Few_Inactive_Accounts_Are_Partial()
    {
        var result = await Run("IA10-partial.json");

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Total inactive accounts: 3", result.Findings);
        Assert.Contains("  Never logged on: 1", result.Findings);
        Assert.Contains("  Last logon > 180 days ago: 2", result.Findings);
        Assert.Contains("svc_scan | LastLogon=Never | Created=", result.Findings);
        Assert.Contains("a.chen | LastLogon=", result.Findings);
        Assert.DoesNotContain("a.chen | LastLogon=Never", result.Findings);
    }

    [Fact]
    public async Task More_Than_Ten_Inactive_Accounts_Fail_And_List_Never_Logged_On_First()
    {
        var result = await Run("IA10-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Total inactive accounts: 12", result.Findings);
        Assert.Contains("  Never logged on: 4", result.Findings);
        Assert.Contains("  Last logon > 180 days ago: 8", result.Findings);
        Assert.Contains("Top 12 most inactive:", result.Findings);

        // Never-logged-on accounts sort first (oldest created first), then the oldest logons.
        var findings = result.Findings;
        Assert.True(findings.IndexOf("new.hire4", StringComparison.Ordinal) < findings.IndexOf("new.hire1", StringComparison.Ordinal));
        Assert.True(findings.IndexOf("new.hire1", StringComparison.Ordinal) < findings.IndexOf("former.user08", StringComparison.Ordinal));
        Assert.True(findings.IndexOf("former.user08", StringComparison.Ordinal) < findings.IndexOf("former.user01", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Both_Searches_Run_From_The_Domain_Root_With_A_180_Day_Threshold()
    {
        var directory = FixtureDirectoryReader.Load("IA10-pass.json");
        var before = DateTime.UtcNow.AddDays(-180).ToFileTimeUtc();

        await new IA10_InactiveAccountsCheck(_ => directory)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(2, directory.Queries.Count);
        Assert.All(directory.Queries, q => Assert.Null(q.SearchBase));
        var threshold = long.Parse(System.Text.RegularExpressions.Regex.Match(directory.Queries[0].Filter, @"lastLogonTimestamp<=(\d+)").Groups[1].Value);
        Assert.InRange(threshold, before, DateTime.UtcNow.AddDays(-180).ToFileTimeUtc());
        Assert.Equal(new[] { "sAMAccountName", "whenCreated" }, directory.Queries[1].Properties);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA10_InactiveAccountsCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA01PrivilegedGroupsCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader) =>
        new IA01_PrivilegedGroupsCheck(_ => reader)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Active_Members_And_No_Orphans_Pass()
    {
        var reader = FixtureDirectoryReader.Load("IA01-pass.json");
        var result = await Run(reader);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Total privileged group members: 6", result.Findings);
        Assert.Contains("Schema Admins: 0 member(s).", result.Findings);
        Assert.Contains("INFO: 2 nested group(s) detected (review for hidden privilege).", result.Findings);
        Assert.DoesNotContain("WARNING", result.Findings);
        Assert.Contains("a.admin | LastLogon=", result.Evidence);
        Assert.Contains("[NESTED GROUP] Domain Admins", result.Evidence);

        // Each group lookup stays a FindOne; the adminCount sweep is a full search.
        var groupQueries = reader.Queries.Where(q => q.Filter.StartsWith("(&(objectClass=group)", StringComparison.Ordinal)).ToList();
        Assert.Equal(4, groupQueries.Count);
        Assert.All(groupQueries, q => Assert.Equal(1, q.SizeLimit));
        Assert.Equal(0, reader.Queries.Single(q => q.Filter.Contains("(adminCount=1)", StringComparison.Ordinal)).SizeLimit);
    }

    [Fact]
    public async Task Stale_NeverExpiring_Member_And_AdminCount_Orphan_Fail()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA01-fail.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("WARNING: 1 member(s) have not logged on in >90 days.", result.Findings);
        Assert.Contains("WARNING: 1 member(s) have PasswordNeverExpires set.", result.Findings);
        Assert.Contains("ORPHAN: former.admin has adminCount=1 but is not in a known privileged group.", result.Findings);
        Assert.Contains("WARNING: 1 account(s) with adminCount=1 not in expected privileged groups.", result.Findings);
        Assert.DoesNotContain("Schema Admins:", result.Findings);
        Assert.Contains("[STALE] [PwdNeverExpires]", result.Evidence);
        Assert.Contains("  Group not found.", result.Evidence);
    }

    [Fact]
    public async Task Unreadable_Member_Is_Noted_Without_Failing_The_Check()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA01-fail.json"));

        Assert.Contains("CN=Partner Admin,OU=Admins,DC=emea,DC=corp,DC=example (could not read details)", result.Evidence);
        Assert.Contains("Domain Admins: 3 member(s).", result.Findings);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA01_PrivilegedGroupsCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

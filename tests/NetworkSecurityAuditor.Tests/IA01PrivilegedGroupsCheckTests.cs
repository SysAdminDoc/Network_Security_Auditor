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
        // Administrators counts a.admin too, now that it's expanded through Domain Admins.
        Assert.Contains("Total privileged group members: 7", result.Findings);
        Assert.Contains("Administrators: 4 member(s).", result.Findings);
        Assert.Contains("Schema Admins: 0 member(s).", result.Findings);
        Assert.Contains("INFO: 2 nested group(s) detected (review for hidden privilege).", result.Findings);
        Assert.DoesNotContain("WARNING", result.Findings);
        // a.admin is already listed under Domain Admins, so reaching it through Administrators isn't hidden privilege.
        Assert.DoesNotContain("NESTED:", result.Findings);
        Assert.Contains("a.admin | LastLogon=", result.Evidence);
        Assert.Contains("[NESTED GROUP] Domain Admins", result.Evidence);
        Assert.Contains("| Path=Administrators > Domain Admins > a.admin", result.Evidence);
        // krbtgt always has adminCount=1, and a Backup Operators member is protected too: neither is an orphan.
        Assert.DoesNotContain("ORPHAN", result.Findings);
        Assert.Contains("krbtgt: protected account (RID 502), adminCount=1 is expected", result.Evidence);
        Assert.Contains("b.backup: protected through Backup Operators, adminCount=1 is expected", result.Evidence);

        // Each group lookup is a FindOne by SID; membership and the adminCount sweep are full searches.
        var groupQueries = reader.Queries.Where(q => q.Filter.StartsWith("(objectSid=", StringComparison.Ordinal)).ToList();
        Assert.Equal(4, groupQueries.Count);
        Assert.All(groupQueries, q => Assert.Equal(1, q.SizeLimit));
        Assert.DoesNotContain(reader.Queries, q => q.Filter.Contains("(cn=", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, reader.Queries.Single(q => q.Filter.Contains("(adminCount=1)", StringComparison.Ordinal)).SizeLimit);
        Assert.Equal(4, reader.Queries.Count(q => q.Filter.Contains("(memberOf:1.2.840.113556.1.4.1941:=", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Nested_Members_Show_Their_Path_And_Count_Toward_Staleness()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA01-nested.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Domain Admins: 4 member(s).", result.Findings);
        Assert.Contains("WARNING: 1 member(s) have not logged on in >90 days.", result.Findings);
        Assert.Contains("NESTED: Domain Admins > Tier0-Ops > alice", result.Findings);
        Assert.Contains("NESTED: Domain Admins > Tier0-Ops > legacy.ops", result.Findings);
        // Nested members of a privileged group aren't adminCount orphans.
        Assert.DoesNotContain("ORPHAN", result.Findings);
        Assert.Matches(@"legacy\.ops \| LastLogon=\d{4}-\d{2}-\d{2} \[STALE\] \| Path=Domain Admins > Tier0-Ops > legacy\.ops", result.Evidence);
        Assert.Contains("[NESTED GROUP] Tier0-Ops", result.Evidence);
    }

    [Theory]
    [InlineData("IA01-pass")]
    [InlineData("IA01-fail")]
    [InlineData("IA01-nested")]
    public async Task Localized_Group_Names_Give_The_Same_Result(string fixture)
    {
        var english = await Run(FixtureDirectoryReader.Load(fixture + ".json"));
        var german = await Run(FixtureDirectoryReader.Load(fixture + "-de.json"));

        Assert.NotEqual(CheckStatus.Error, german.Status);
        Assert.Equal(english.Status, german.Status);
        Assert.Contains("Domänen-Admins:", german.Findings);
        Assert.Equal(english.Findings, LocalizedDirectoryFixtures.Delocalize(german.Findings));
    }

    [Fact]
    public async Task Stale_NeverExpiring_Member_And_AdminCount_Orphan_Fail()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA01-fail.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("WARNING: 1 member(s) have not logged on in >90 days.", result.Findings);
        Assert.Contains("WARNING: 1 member(s) have PasswordNeverExpires set.", result.Findings);
        // former.admin is only in VPN Users, which isn't a protected group, so it's a real orphan.
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

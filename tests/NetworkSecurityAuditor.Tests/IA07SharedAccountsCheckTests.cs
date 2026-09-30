using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA07SharedAccountsCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader) =>
        new IA07_SharedAccountsCheck(_ => reader)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Builtin_Administrator_And_Disabled_Matches_Pass()
    {
        var reader = FixtureDirectoryReader.Load("IA07-pass.json");
        var result = await Run(reader);

        // The enabled built-in Administrator matches "admin", but RID 500 isn't a shared account.
        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Shared/generic accounts found: 1", result.Findings);
        Assert.DoesNotContain("Enabled shared accounts", result.Findings);
        Assert.Contains("Not counted: the built-in Administrator (RID 500), which IA01 reviews.", result.Findings);
        Assert.Contains("Administrator | skipped: built-in Administrator (RID 500), reviewed under IA01", result.Evidence);
        Assert.DoesNotContain("Administrator | Enabled=", result.Evidence);
        Assert.Contains("test.user | Enabled=False | PwdAge=400d", result.Evidence);
        Assert.Equal(9, reader.Queries.Count);
    }

    [Fact]
    public async Task Builtin_Administrator_Is_Known_By_Rid_Not_By_Name()
    {
        // Renamed RID 500 is skipped; an ordinary account that happens to be called "Administrator" is not.
        const string domain = "S-1-5-21-1004336348-1177238915-682003330";
        var empty = string.Join(",", new[] { "shared", "generic", "scanner", "reception", "kiosk", "training", "test", "temp" }
            .Select(p => $$"""{ "base": null, "filter": "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{{p}}*))", "results": [] }"""));
        var reader = FixtureDirectoryReader.FromJson($$"""
            {
              "entries": { "(domain)": { "objectSid": { "$sid": "{{domain}}" } } },
              "searches": [
                {{empty}},
                { "base": null, "filter": "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*admin*))", "results": [
                  { "sAMAccountName": "corp-admin", "distinguishedName": "CN=corp-admin,CN=Users,DC=corp,DC=example",
                    "userAccountControl": 512, "objectSid": { "$sid": "{{domain}}-500" } },
                  { "sAMAccountName": "Administrator", "distinguishedName": "CN=Administrator,OU=Decoys,DC=corp,DC=example",
                    "userAccountControl": 512, "objectSid": { "$sid": "{{domain}}-1105" } } ] }
              ]
            }
            """);
        var result = await Run(reader);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Shared/generic accounts found: 1", result.Findings);
        Assert.Contains("corp-admin | skipped: built-in Administrator (RID 500)", result.Evidence);
        Assert.Contains("Administrator | Enabled=True", result.Evidence);
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

        // shared.frontdesk and scanner are enabled shared accounts; the built-in Administrator isn't one.
        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Shared/generic accounts found: 3", result.Findings);
        Assert.Contains("Enabled shared accounts: 2", result.Findings);
        Assert.Contains("Enabled with password > 180 days old: 2", result.Findings);
        Assert.Contains("shared.frontdesk | Enabled=True | PwdAge=400d", result.Evidence);
        Assert.Contains("Administrator | skipped: built-in Administrator (RID 500)", result.Evidence);
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

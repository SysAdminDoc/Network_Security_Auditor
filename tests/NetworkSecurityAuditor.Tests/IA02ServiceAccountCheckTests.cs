using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA02ServiceAccountCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader) =>
        new IA02_ServiceAccountCheck(_ => reader)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task No_Spn_Users_With_Gmsa_Passes()
    {
        var reader = FixtureDirectoryReader.Load("IA02-pass.json");
        var result = await Run(reader);

        // krbtgt and a disabled account both carry SPNs, but neither can be kerberoasted.
        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Kerberoastable accounts (user with SPN): 0", result.Findings);
        Assert.Contains("Not counted: krbtgt and 1 disabled account(s) with an SPN.", result.Findings);
        Assert.Contains("krbtgt | skipped: KDC account (RID 502)", result.Evidence);
        Assert.Contains("legacy.web | SPN=HTTP/oldweb.corp.example | skipped: disabled", result.Evidence);
        Assert.Contains("Service-pattern accounts found: 1", result.Findings);
        Assert.Contains("gMSA accounts: 2", result.Findings);
        Assert.DoesNotContain("RECOMMENDATION", result.Findings);
        Assert.Contains("svc_print | Enabled=True | PwdAge=120d | Pattern=svc", result.Evidence);
        Assert.Contains("gmsa-iis$", result.Evidence);
        // Domain Admins by SID and its members, one SPN search, one per naming pattern, one gMSA search.
        Assert.Equal(12, reader.Queries.Count);
        Assert.Contains(reader.Queries, q => q.Filter == "(objectSid=S-1-5-21-1004336348-1177238915-682003330-512)");
    }

    [Fact]
    public async Task Old_Password_Domain_Admin_Spn_Account_Fails()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA02-fail.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Kerberoastable accounts (user with SPN): 2", result.Findings);
        Assert.Contains("CRITICAL: 1 SPN account(s) have passwords older than 1 year.", result.Findings);
        Assert.Contains("CRITICAL: 1 SPN account(s) are in Domain Admins", result.Findings);
        Assert.Contains("RECOMMENDATION: No gMSAs detected.", result.Findings);
        // svc_sql is a Domain Admin only through SQL Admins, which memberOf alone doesn't show.
        Assert.Contains("svc_sql | SPN=MSSQLSvc/sql01.corp.example:1433 | PwdAge=900d [PWD>900d] [DOMAIN ADMIN] Path=Domain Admins > SQL Admins > svc_sql", result.Evidence);
        Assert.Contains("svc_web | SPN=HTTP/intranet.corp.example | PwdAge=60d", result.Evidence);
        Assert.DoesNotContain("svc_web | SPN=HTTP/intranet.corp.example | PwdAge=60d [DOMAIN ADMIN]", result.Evidence);
        Assert.Contains("svc_sql | Enabled=True | PwdAge=900d | Pattern=svc", result.Evidence);
        Assert.DoesNotContain("Not counted", result.Findings);
        // svc_sql matches "svc" and "sql" but is one account.
        Assert.Contains("Service-pattern accounts found: 2", result.Findings);
        Assert.DoesNotContain("Pattern=sql", result.Evidence);
    }

    [Fact]
    public async Task Localized_Domain_Admins_Give_The_Same_Result()
    {
        var english = await Run(FixtureDirectoryReader.Load("IA02-fail.json"));
        var german = await Run(FixtureDirectoryReader.Load("IA02-fail-de.json"));

        Assert.Equal(CheckStatus.Fail, german.Status);
        Assert.Contains("CRITICAL: 1 SPN account(s) are in Domänen-Admins", german.Findings);
        Assert.Equal(english.Findings, LocalizedDirectoryFixtures.Delocalize(german.Findings));
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA02_ServiceAccountCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

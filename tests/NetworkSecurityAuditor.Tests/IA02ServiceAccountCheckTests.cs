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

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Kerberoastable accounts (user with SPN): 0", result.Findings);
        Assert.Contains("Service-pattern accounts found: 1", result.Findings);
        Assert.Contains("gMSA accounts: 2", result.Findings);
        Assert.DoesNotContain("RECOMMENDATION", result.Findings);
        Assert.Contains("svc_print | Enabled=True | PwdAge=120d | Pattern=svc", result.Evidence);
        Assert.Contains("gmsa-iis$", result.Evidence);
        // One SPN search, one per naming pattern, one gMSA search.
        Assert.Equal(10, reader.Queries.Count);
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
        Assert.Contains("svc_sql | SPN=MSSQLSvc/sql01.corp.example:1433 | PwdAge=900d [PWD>900d] [DOMAIN ADMIN]", result.Evidence);
        Assert.Contains("svc_web | SPN=HTTP/intranet.corp.example | PwdAge=60d", result.Evidence);
        Assert.Contains("svc_sql | Enabled=True | PwdAge=900d | Pattern=svc", result.Evidence);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA02_ServiceAccountCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

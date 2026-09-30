using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA05PasswordPolicyCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader) =>
        new IA05_PasswordPolicyCheck(_ => reader)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Hardened_Policy_With_Pso_Passes()
    {
        var reader = FixtureDirectoryReader.Load("IA05-pass.json");
        var result = await Run(reader);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: Minimum password length is 14.", result.Findings);
        Assert.Contains("PASS: Maximum password age is 60 days.", result.Findings);
        Assert.Contains("PASS: Lockout duration is 30 minutes.", result.Findings);
        Assert.Contains("Fine-grained password policies (PSOs): 1", result.Findings);
        Assert.DoesNotContain("FAIL", result.Findings);
        Assert.Contains("PSO: PSO-Admins | Precedence=10 | MinLen=20", result.Evidence);

        var psoQuery = Assert.Single(reader.Queries);
        Assert.Equal("CN=Password Settings Container,CN=System,DC=corp,DC=example", psoQuery.SearchBase);
        Assert.Equal(100, psoQuery.PageSize);
    }

    [Fact]
    public async Task Default_Domain_Policy_Fails_On_Length_And_Lockout()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA05-fail.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: Minimum password length is 7 (recommended >= 12).", result.Findings);
        Assert.Contains("PASS: Maximum password age is 42 days.", result.Findings);
        Assert.Contains("FAIL: Account lockout is DISABLED (lockoutThreshold=0). Brute-force risk.", result.Findings);
        Assert.DoesNotContain("Lockout duration", result.Findings);
        Assert.Contains("Fine-grained password policies (PSOs): 0", result.Findings);
    }

    [Fact]
    public async Task Never_Expiring_Passwords_Fail_And_Unreadable_Pso_Container_Is_Noted()
    {
        var result = await Run(FixtureDirectoryReader.Load("IA05-fail-no-expiry.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: Maximum password age is set to 0 (passwords never expire).", result.Findings);
        Assert.Contains("FAIL: Password complexity is NOT enabled.", result.Findings);
        Assert.Contains("WARNING: Lockout threshold is 3 (very aggressive, may cause lockouts).", result.Findings);
        Assert.Contains("WARNING: Lockout duration is only 10 minutes (consider >= 15).", result.Findings);
        Assert.Contains("Fine-grained password policies: could not query.", result.Findings);
        Assert.Contains("Could not query PSO container (may not exist or access denied).", result.Evidence);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA05_PasswordPolicyCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

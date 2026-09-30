using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA11KerberosEncryptionCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new IA11_KerberosEncryptionCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Fresh_Krbtgt_And_Aes_Service_Accounts_Pass()
    {
        var result = await Run("IA11-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: krbtgt password age is 30 days.", result.Findings);
        Assert.Contains("Service accounts with SPNs: 2", result.Findings);
        Assert.Contains("  AES-capable: 2", result.Findings);
        Assert.Contains("  RC4-only (no AES): 0", result.Findings);
        Assert.Contains("svc_web | EncTypes=0x1C (RC4-HMAC+AES128+AES256)", result.Evidence);
        Assert.Contains("Domain msDS-SupportedEncryptionTypes = 0x18", result.Evidence);
    }

    [Fact]
    public async Task Old_Krbtgt_Rc4_Only_And_Des_Accounts_Fail()
    {
        var result = await Run("IA11-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("CRITICAL: krbtgt password is 400 days old (Golden Ticket risk). Reset immediately.", result.Findings);
        Assert.Contains("Service accounts with SPNs: 4", result.Findings);
        Assert.Contains("  No encryption type set: 1", result.Findings);
        Assert.Contains("CRITICAL: 1 account(s) support DES encryption (broken, must be disabled).", result.Findings);
        Assert.Contains("FAIL: 1 account(s) support only RC4 (vulnerable to Kerberoasting). Enable AES.", result.Findings);
        Assert.Contains("svc_legacy | EncTypes=0x0 (DES(UAC))", result.Evidence);
        Assert.Contains("svc_print | EncTypes=0x0 (None/Default)", result.Evidence);
        // The domain root has no msDS-SupportedEncryptionTypes value.
        Assert.Contains("Domain msDS-SupportedEncryptionTypes = 0x0", result.Evidence);
    }

    [Fact]
    public async Task Krbtgt_Is_Read_With_A_Single_Result_Search_From_The_Domain_Root()
    {
        var directory = FixtureDirectoryReader.Load("IA11-pass.json");

        await new IA11_KerberosEncryptionCheck(_ => directory)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(2, directory.Queries.Count);
        Assert.Equal(1, directory.Queries[0].SizeLimit);
        Assert.Equal(0, directory.Queries[1].SizeLimit);
        Assert.All(directory.Queries, q => Assert.Null(q.SearchBase));
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA11_KerberosEncryptionCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

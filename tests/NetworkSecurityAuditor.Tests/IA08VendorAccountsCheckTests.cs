using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA08VendorAccountsCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new IA08_VendorAccountsCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task No_Vendor_Accounts_Passes()
    {
        var result = await Run("IA08-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Vendor/guest accounts found: 0", result.Findings);
        Assert.Contains("No vendor/guest accounts detected matching common naming patterns.", result.Findings);
    }

    [Fact]
    public async Task Vendor_Accounts_With_Expiry_Or_Disabled_Are_Partial()
    {
        var result = await Run("IA08-partial.json");

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Vendor/guest accounts found: 2", result.Findings);
        Assert.Contains("vendor.acme | Enabled=True | Expires=2026-12-31 | LastLogon=", result.Findings);
        Assert.Contains("Guest | Enabled=False | Expires=Never | LastLogon=Never", result.Findings);
        Assert.DoesNotContain("[NO EXPIRY]", result.Findings);
    }

    [Fact]
    public async Task Enabled_Vendor_Accounts_Without_Expiry_Fail_And_Count_Once()
    {
        var result = await Run("IA08-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        // external.vendor01 matches both "vendor" and "extern"; it's one account.
        Assert.Contains("Vendor/guest accounts found: 4", result.Findings);
        Assert.Contains("CRITICAL: 2 enabled vendor/guest account(s) have NO expiration date set.", result.Findings);
        Assert.Contains("contractor.jsmith | Enabled=True | Expires=Never | LastLogon=", result.Findings);
        Assert.Contains("external.vendor01 | Enabled=True | Expires=Never | LastLogon=Never [NO EXPIRY]", result.Findings);
        Assert.Contains("partner.globex | Enabled=True | Expires=2027-03-31", result.Findings);
        Assert.Single(result.Findings.Split('\n'), line => line.Contains("external.vendor01", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Every_Naming_Pattern_Is_Searched_From_The_Domain_Root()
    {
        var directory = FixtureDirectoryReader.Load("IA08-pass.json");

        await new IA08_VendorAccountsCheck(_ => directory)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(9, directory.Queries.Count);
        Assert.All(directory.Queries, q => Assert.Null(q.SearchBase));
        Assert.Contains(directory.Queries, q => q.Filter == "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*contractor*))");
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA08_VendorAccountsCheck(_ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}

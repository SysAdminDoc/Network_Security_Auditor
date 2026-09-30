using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA03MfaSignalsCheckTests
{
    private const string RdpTcp = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string Hello = @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork";
    private const string SystemPolicies = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    private static Task<CheckResult> Run(FixtureRegistryReader registry) =>
        new IA03_MfaSignalsCheck(registry).ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Nla_And_Hello_For_Business_Pass()
    {
        var registry = new FixtureRegistryReader()
            .Set(RdpTcp, "UserAuthentication", 1)
            .Set(Hello, "Enabled", 1)
            .Set(Hello, "RequireSecurityDevice", 1);

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.StartsWith("MFA/Strong Auth signals found: 2", result.Findings);
        Assert.Contains("Hardware security device (TPM) required.", result.Findings);
    }

    [Fact]
    public async Task One_Mfa_Agent_Alone_Is_Partial()
    {
        var registry = new FixtureRegistryReader()
            .Set(RdpTcp, "UserAuthentication", 0)
            .Installed("Duo Authentication for Windows Logon x64");

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("FAIL: RDP NLA is DISABLED.", result.Findings);
        Assert.Contains("MFA agents detected: Duo Security", result.Findings);
    }

    [Fact]
    public async Task No_Signals_Fails()
    {
        var registry = new FixtureRegistryReader()
            .Set(RdpTcp, "UserAuthentication", 0)
            .Set(SystemPolicies, "scforceoption", 0)
            .Installed("7-Zip 24.08 (x64)");

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.StartsWith("MFA/Strong Auth signals found: 0", result.Findings);
        Assert.Contains("No MFA agent software detected", result.Findings);
    }

    [Fact]
    public async Task Smart_Card_Enforcement_And_Adfs_Count_As_Signals()
    {
        var registry = new FixtureRegistryReader()
            .Set(SystemPolicies, "scforceoption", 1);
        registry.AddKey(@"HKLM\SOFTWARE\Microsoft\ADFS");

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Smart card logon is enforced", result.Findings);
        Assert.Contains("ADFS registry key detected", result.Findings);
    }
}

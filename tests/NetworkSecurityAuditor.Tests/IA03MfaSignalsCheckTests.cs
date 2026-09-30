using System.Text.RegularExpressions;
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
    public async Task Smart_Card_Enforcement_Counts_But_Adfs_Does_Not()
    {
        var registry = new FixtureRegistryReader()
            .Set(SystemPolicies, "scforceoption", 1);
        registry.AddKey(@"HKLM\SOFTWARE\Microsoft\ADFS");

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.StartsWith("MFA/Strong Auth signals found: 1", result.Findings);
        Assert.Contains("Smart card logon is enforced", result.Findings);
        Assert.Contains("ADFS alone isn't MFA", result.Findings);
    }

    [Fact]
    public async Task Programs_That_Only_Contain_An_Agent_Name_Add_No_Signal()
    {
        var registry = new FixtureRegistryReader()
            .Set(RdpTcp, "UserAuthentication", 0)
            .Installed("Microsoft Visual C++ 2015-2022 Universal CRT")
            .Installed("Microsoft Visual C++ Universal CRT")
            .Installed("Snipping Tool")
            .Installed("Duolingo")
            .Installed("Thales Display Driver")
            .Installed("CyberArk Endpoint Privilege Manager");

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.StartsWith("MFA/Strong Auth signals found: 0", result.Findings);
        Assert.Contains("No MFA agent software detected", result.Findings);
        Assert.DoesNotContain("FOUND:", result.Evidence);
    }

    [Theory]
    [InlineData("Duo Authentication for Windows Logon x64", "Duo Security")]
    [InlineData("Okta Verify", "Okta Verify")]
    [InlineData("YubiKey Manager", "YubiKey")]
    [InlineData("RSA Authentication Agent for Microsoft Windows", "RSA SecurID")]
    [InlineData("PingID Integration for Windows Login", "PingID")]
    [InlineData("NPS Extension For Azure MFA", "Azure AD MFA")]
    [InlineData("WatchGuard AuthPoint Agent for Windows", "WatchGuard AuthPoint")]
    public async Task Named_Mfa_Agent_Adds_One_Signal(string program, string label)
    {
        var registry = new FixtureRegistryReader()
            .Set(RdpTcp, "UserAuthentication", 0)
            .Installed(program);

        var result = await Run(registry);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.StartsWith("MFA/Strong Auth signals found: 1", result.Findings);
        Assert.Contains($"MFA agents detected: {label}", result.Findings);
    }

    [Fact]
    public void Script_Uses_The_Same_Agent_List()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        var script = File.ReadAllText(Path.Combine(dir!.FullName, "NetworkSecurityAudit.ps1"));
        var list = Regex.Match(script, @"function Get-Ia03MfaAgent \{\s+param\(\[string\]\$DisplayName\)\s+\$agents = \[ordered\]@\{(?<list>[^}]*)\}");

        Assert.True(list.Success, "Get-Ia03MfaAgent's agent list not found in NetworkSecurityAudit.ps1");
        Assert.Equal(
            IA03_MfaSignalsCheck.MfaAgents.Select(a => $"{a.Phrase}={a.Label}"),
            Regex.Matches(list.Groups["list"].Value, "'([^']*)'='([^']*)'").Select(m => $"{m.Groups[1].Value}={m.Groups[2].Value}"));
    }
}

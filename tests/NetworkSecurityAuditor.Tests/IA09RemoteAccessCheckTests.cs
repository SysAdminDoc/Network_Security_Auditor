using System.Net.NetworkInformation;
using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;
using Adapter = NetworkSecurityAuditor.Checks.IdentityAccess.IA09_RemoteAccessCheck.NetworkAdapter;

namespace NetworkSecurityAuditor.Tests;

public class IA09RemoteAccessCheckTests
{
    private const string TerminalServer = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcp = TerminalServer + @"\WinStations\RDP-Tcp";

    private static readonly Adapter Ethernet = new("Ethernet", "Intel(R) Ethernet Connection I219-LM", NetworkInterfaceType.Ethernet, OperationalStatus.Up);

    private static Task<CheckResult> Run(FixtureRegistryReader registry, params Adapter[] adapters) =>
        new IA09_RemoteAccessCheck(registry, () => adapters)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Rdp_With_Nla_And_One_Rmm_Agent_Passes()
    {
        var registry = new FixtureRegistryReader()
            .Set(TerminalServer, "fDenyTSConnections", 0)
            .Set(RdpTcp, "UserAuthentication", 1)
            .Set(RdpTcp, "PortNumber", 3389)
            .Installed("ConnectWise Automate Remote Agent");

        var result = await Run(registry, Ethernet,
            new Adapter("Corp VPN", "PANGP Virtual Ethernet Adapter GlobalProtect", NetworkInterfaceType.Ethernet, OperationalStatus.Down));

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("RDP is ENABLED on port 3389.", result.Findings);
        Assert.Contains("PASS: NLA is enabled.", result.Findings);
        Assert.Contains("VPN adapters detected: Corp VPN (PANGP Virtual Ethernet Adapter GlobalProtect)", result.Findings);
        Assert.DoesNotContain("Ethernet Connection I219", result.Findings);
    }

    [Fact]
    public async Task Rdp_Without_Nla_Fails()
    {
        var registry = new FixtureRegistryReader()
            .Set(TerminalServer, "fDenyTSConnections", 0)
            .Set(RdpTcp, "UserAuthentication", 0)
            .Set(RdpTcp, "PortNumber", 3390);

        var result = await Run(registry, Ethernet);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: NLA (Network Level Authentication) is NOT enabled for RDP.", result.Findings);
        Assert.Contains("Non-standard RDP port (3390)", result.Findings);
        Assert.Contains("No VPN adapters detected.", result.Findings);
    }

    [Fact]
    public async Task Three_Remote_Tools_Fail_Even_With_Rdp_Off()
    {
        var registry = new FixtureRegistryReader()
            .Set(TerminalServer, "fDenyTSConnections", 1)
            .Installed("TeamViewer")
            .Installed("AnyDesk")
            .Installed("NinjaRMMAgent");

        var result = await Run(registry, Ethernet);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("RDP is disabled.", result.Findings);
        Assert.Contains("WARNING: 3 remote management tools detected.", result.Findings);
    }

    [Fact]
    public async Task Adapter_Enumeration_Failure_Is_Noted_Without_Failing_The_Check()
    {
        var result = await new IA09_RemoteAccessCheck(
                new FixtureRegistryReader().Set(TerminalServer, "fDenyTSConnections", 1),
                () => throw new NetworkInformationException(5))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Error enumerating adapters:", result.Evidence);
    }
}

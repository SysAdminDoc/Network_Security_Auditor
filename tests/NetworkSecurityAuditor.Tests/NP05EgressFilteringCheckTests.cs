namespace NetworkSecurityAuditor.Tests;

using System.Management;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;
using OutboundDefault = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP05_EgressFilteringCheck.OutboundDefault;

public sealed class NP05EgressFilteringCheckTests
{
    private static FirewallRuleSnapshot Outbound(string name, int action, string? program = null, string? service = null) =>
        new($"{{{name}}}", name, string.Empty, Direction: 2, Action: action, Protocol: "TCP",
            LocalPorts: [], RemotePorts: [], RemoteAddresses: [], Program: program, Service: service);

    private static IReadOnlyList<OutboundDefault> AllBlock() =>
    [
        new("Domain", true, "active store"),
        new("Private", true, "active store"),
        new("Public", true, "active store"),
    ];

    [Fact]
    public async Task Reads_The_Active_Store_So_A_Group_Policy_Block_Rule_Counts()
    {
        var gpoBlock = Outbound("GPO - Block SMB out", action: 4);
        var local = Outbound("Local allow", action: 2, program: @"C:\Tools\app.exe");
        var check = new NP05_EgressFilteringCheck(
            (_, store) => store == FirewallRuleReader.ActiveStore ? [local, gpoBlock] : [local],
            readOutboundDefaults: AllBlock);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Outbound firewall rules: 2 total, 1 allow, 1 block.", result.Findings);
        Assert.Contains("Domain: Default outbound is BLOCK (good).", result.Findings);
    }

    [Fact]
    public async Task Program_Scoped_Outbound_Allows_Are_Application_Aware_Not_Any_Any()
    {
        var scoped = Enumerable.Range(1, 5).Select(i => Outbound($"App {i}", action: 2, program: $@"C:\Apps\app{i}.exe")).ToList();
        var check = new NP05_EgressFilteringCheck((_, _) => [.. scoped, Outbound("Block telemetry", action: 4)], readOutboundDefaults: AllBlock);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.DoesNotContain("ANY/ANY", result.Evidence);

        var open = Enumerable.Range(1, 4).Select(i => Outbound($"Open {i}", action: 2, program: "Any")).ToList();
        var failing = await new NP05_EgressFilteringCheck((_, _) => [.. open, Outbound("Block telemetry", action: 4)], readOutboundDefaults: AllBlock)
            .ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
        Assert.Equal(CheckStatus.Fail, failing.Status);
        Assert.Contains("4 outbound ALLOW rules with no port, address or program restriction", failing.Findings);
    }

    [Fact]
    public async Task Default_Outbound_Allow_From_The_Active_Store_Is_Flagged()
    {
        var check = new NP05_EgressFilteringCheck(
            (_, _) => [Outbound("Block telemetry", action: 4)],
            readOutboundDefaults: () => [new("Domain", false, "active store"), new("Private", true, "active store"), new("Public", null, "active store")]);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("WARNING: Domain default outbound action is ALLOW.", result.Findings);
        Assert.Contains("Public: DefaultOutboundAction = Unknown (active store)", result.Evidence);
        Assert.DoesNotContain("Public default outbound action is ALLOW", result.Findings);
    }

    [Theory]
    [InlineData((ushort)4, true)]
    [InlineData((ushort)2, false)]
    [InlineData((ushort)0, false)]
    [InlineData((ushort)1, null)]
    [InlineData("Block", null)]
    public void Wmi_Outbound_Action_Values_Map_To_Block_Or_Allow(object value, bool? expected)
    {
        Assert.Equal(expected, NP05_EgressFilteringCheck.BlocksOutbound(value));
    }

    [Fact]
    public async Task Without_Elevation_Falls_Back_To_Netsh_Verbose_And_Skips_Program_Scoped_Rules()
    {
        string? arguments = null;
        var check = new NP05_EgressFilteringCheck(
            (_, _) => throw new ManagementException("Access denied"),
            (_, args, _) => { arguments = args; return NetshOutboundVerbose; },
            AllBlock);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal("advfirewall firewall show rule name=all dir=out verbose", arguments);
        Assert.Contains("Outbound firewall rules: 3 total, 2 allow, 1 block.", result.Findings);
        Assert.Contains("ANY/ANY ALLOW OUT: Wide open out", result.Evidence);
        Assert.DoesNotContain("ANY/ANY ALLOW OUT: Google Chrome", result.Evidence);
        Assert.Contains("NOTE: Rule filters couldn't be read", result.Findings);
        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Group Policy and service-added rules weren't checked, so this is Partial.", result.Findings);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new NP05_EgressFilteringCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.Contains("(active store)", result.Evidence);
        Assert.DoesNotContain("netsh fallback error", result.Evidence);
    }

    private const string NetshOutboundVerbose = """
        Rule Name:                            Google Chrome (mDNS-Out)
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            Out
        RemoteIP:                             Any
        RemotePort:                           Any
        Program:                              C:\Program Files\Google\Chrome\Application\chrome.exe
        Action:                               Allow

        Rule Name:                            Wide open out
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            Out
        RemoteIP:                             Any
        RemotePort:                           Any
        Program:                              Any
        Action:                               Allow

        Rule Name:                            Block telemetry
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            Out
        RemoteIP:                             13.64.0.0/11
        Action:                               Block

        Ok.
        """;
}

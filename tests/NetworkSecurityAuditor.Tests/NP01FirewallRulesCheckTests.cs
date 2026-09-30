namespace NetworkSecurityAuditor.Tests;

using System.Management;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;

public sealed class NP01FirewallRulesCheckTests
{
    private static FirewallRuleSnapshot InboundAllow(string name, string[]? localPorts = null, string[]? remote = null,
        string? program = null, string? package = null, string? service = null, string? owner = null) =>
        new($"{{{name}}}", name, string.Empty, Direction: 1, Action: 2, Protocol: "TCP",
            LocalPorts: localPorts ?? [], RemotePorts: [], RemoteAddresses: remote ?? [],
            Program: program, Package: package, Service: service, Owner: owner);

    private static readonly FirewallRuleSnapshot LocalScopedRule = InboundAllow("Remote Desktop - User Mode (TCP-In)", localPorts: ["3389"]);

    [Fact]
    public async Task Reads_The_Active_Store_So_A_Group_Policy_Rule_Is_Seen()
    {
        var gpoRule = InboundAllow("GPO - Allow all inbound");
        var stores = new List<string?>();
        var check = new NP01_FirewallRulesCheck((ct, store) =>
        {
            stores.Add(store);
            return store == FirewallRuleReader.ActiveStore ? [LocalScopedRule, gpoRule] : [LocalScopedRule];
        });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal([FirewallRuleReader.ActiveStore], stores);
        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("GPO - Allow all inbound", result.Findings);
        Assert.Contains("active store", result.Evidence);
    }

    [Fact]
    public async Task Any_Port_Rules_Scoped_To_A_Program_Package_Service_Or_Owner_Are_Not_Any_Any()
    {
        var check = new NP01_FirewallRulesCheck((_, _) =>
        [
            InboundAllow("Google Chrome (mDNS-In)", program: @"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            InboundAllow("Xbox Game Bar", package: "S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742"),
            InboundAllow("Delivery Optimization (TCP-In)", service: "DoSvc"),
            InboundAllow("Per-user app", owner: "S-1-5-21-1-2-3-1001"),
            InboundAllow("Any program, any address", program: "Any"),
        ]);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("CRITICAL: 1 inbound ALLOW rule(s)", result.Findings);
        Assert.Contains("Any program, any address", result.Findings);
        Assert.DoesNotContain("Google Chrome", result.Findings);
    }

    [Fact]
    public async Task Without_Elevation_Falls_Back_To_Netsh_And_Says_Group_Policy_Rules_Are_Missing()
    {
        string? arguments = null;
        var check = new NP01_FirewallRulesCheck(
            (_, _) => throw new ManagementException("Access denied"),
            (file, args, _) =>
            {
                Assert.Equal("netsh", file);
                arguments = args;
                return NetshInboundVerbose;
            });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal("advfirewall firewall show rule name=all dir=in verbose", arguments);
        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Inbound firewall rules: 3 total, 3 allow rules.", result.Findings);
        Assert.Contains("CRITICAL: 1 inbound ALLOW rule(s)", result.Findings);
        Assert.Contains("  - Wide open", result.Findings);
        Assert.Contains("NOTE: Rule filters couldn't be read", result.Findings);
        Assert.Contains("local store only", result.Evidence);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new NP01_FirewallRulesCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.Contains("[Windows Firewall Rules Analysis - active store", result.Evidence);
        Assert.DoesNotContain("netsh fallback error", result.Evidence);
    }

    // Recorded from netsh on Windows 11 25H2 (English), trimmed to three rules.
    [Fact]
    public async Task Local_Only_Read_Without_Any_Any_Rules_Is_Partial()
    {
        var wideOpen = NetshInboundVerbose.IndexOf("Rule Name:                            Wide open", StringComparison.Ordinal);
        var check = new NP01_FirewallRulesCheck(
            (_, _) => throw new ManagementException("Access denied"),
            (_, _, _) => NetshInboundVerbose[..wideOpen]);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Inbound firewall rules: 2 total", result.Findings);
        Assert.Contains("Group Policy and service-added rules weren't checked, so this is Partial.", result.Findings);
        Assert.DoesNotContain("PASS:", result.Findings);
    }

    private const string NetshInboundVerbose = """
        Rule Name:                            Google Chrome (mDNS-In)
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            In
        LocalIP:                              Any
        RemoteIP:                             Any
        Protocol:                             UDP
        LocalPort:                            Any
        RemotePort:                           Any
        Program:                              C:\Program Files\Google\Chrome\Application\chrome.exe
        Action:                               Allow

        Rule Name:                            Remote Procedure Call (RPC)
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            In
        RemoteIP:                             Any
        LocalPort:                            Any
        Program:                              Any
        Service:                              RpcSs
        Action:                               Allow

        Rule Name:                            Wide open
        ----------------------------------------------------------------------
        Enabled:                              Yes
        Direction:                            In
        RemoteIP:                             Any
        LocalPort:                            Any
        Program:                              Any
        Action:                               Allow

        Ok.
        """;
}

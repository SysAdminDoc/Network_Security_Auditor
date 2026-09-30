using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;
using Listener = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP02_OpenPortsCheck.ListenerEndpoint;
using PortSnapshot = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP02_OpenPortsCheck.PortSnapshot;

namespace NetworkSecurityAuditor.Tests;

public class EP06_HostFirewallCheckTests
{
    [Fact]
    public async Task ExecuteAsync_Passes_When_Wmi_Profiles_Are_Healthy()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, NoHighRiskListeners);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("All Windows Firewall profiles enabled", result.Findings);
        Assert.Contains("[WMI] Domain", result.Evidence);
    }

    [Fact]
    public async Task ExecuteAsync_Fails_When_Wmi_Profile_Is_Disabled()
    {
        var check = new EP06_HostFirewallCheck(
            () =>
            [
                Profile("Domain", enabled: false),
                Profile("Private"),
                Profile("Public")
            ],
            NoCommands,
            NoHighRiskListeners);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Firewall profile 'Domain' is DISABLED", result.Findings);
    }

    [Fact]
    public async Task ExecuteAsync_Fails_When_Default_Inbound_Action_Is_Not_Block()
    {
        var check = new EP06_HostFirewallCheck(
            () =>
            [
                Profile("Domain", inbound: FirewallDefaultAction.Allow),
                Profile("Private"),
                Profile("Public")
            ],
            NoCommands,
            NoHighRiskListeners);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("default inbound action is Allow; expected Block", result.Findings);
    }

    [Fact]
    public async Task ExecuteAsync_Returns_Partial_When_Dropped_Connection_Logging_Is_Disabled()
    {
        var check = new EP06_HostFirewallCheck(
            () =>
            [
                Profile("Domain", logDropped: false),
                Profile("Private"),
                Profile("Public")
            ],
            NoCommands,
            NoHighRiskListeners);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("dropped-connection logging is disabled", result.Findings);
    }

    [Fact]
    public async Task ExecuteAsync_Uses_Netsh_Fallback_With_Flexible_State_Spacing()
    {
        var check = new EP06_HostFirewallCheck(
            () => throw new InvalidOperationException("CIM unavailable"),
            NetshProfileOutput,
            NoHighRiskListeners);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Firewall profile 'Domain' is DISABLED", result.Findings);
        Assert.Contains("[netsh] Domain", result.Evidence);
    }

    // A stock workstation listens on RPC, NetBIOS, SMB and WinRM. On a private network that's normal.
    [Fact]
    public async Task Default_Workstation_Listeners_Do_Not_Raise_An_Issue()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, _ => new PortSnapshot { Listeners = DefaultWorkstationListeners() });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: No high-risk listeners", result.Findings);
        Assert.DoesNotContain("445", result.Findings);
        Assert.Contains("INFO: TCP 445 (SMB)", result.Evidence);
        Assert.DoesNotContain("netstat", result.Evidence);
    }

    [Fact]
    public async Task Insecure_Listener_Fails()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, _ => new PortSnapshot
        {
            Listeners = [.. DefaultWorkstationListeners(), new("TCP", "0.0.0.0", 23)],
        });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: 1 high-risk listener(s):", result.Findings);
        Assert.Contains("TCP 23 (Telnet) listening on 0.0.0.0 (all interfaces)", result.Findings);
        Assert.DoesNotContain("445", result.Findings);
    }

    [Fact]
    public async Task Role_Port_Reachable_From_A_Public_Network_Fails()
    {
        var smbIn = new FirewallRuleSnapshot("{smb-in}", "File and Printer Sharing (SMB-In)", string.Empty, Direction: 1, Action: 2, Protocol: "TCP",
            LocalPorts: ["445"], RemotePorts: [], RemoteAddresses: [], Profiles: 4, Program: "System");
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, _ => new PortSnapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            FirewallRules = [smbIn],
        });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("TCP 445 (SMB) reachable from a Public-profile network via inbound rule 'File and Printer Sharing (SMB-In)'", result.Findings);
        Assert.DoesNotContain("TCP 135", result.Findings);
    }

    [Fact]
    public async Task Sensitive_Service_Beyond_Loopback_Is_A_Warning()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, _ => new PortSnapshot
        {
            Listeners = [new("TCP", "0.0.0.0", 3389), new("TCP", "127.0.0.1", 1433)],
        });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("TCP 3389 (RDP) listening on 0.0.0.0 (all interfaces)", result.Findings);
        Assert.DoesNotContain("1433", result.Findings);
        Assert.Contains("INFO: TCP 1433 (MSSQL) on loopback only", result.Evidence);
    }

    [Fact]
    public async Task Unreadable_Listeners_Are_Evidence_Only()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoCommands, _ => new PortSnapshot { ListenerError = "The parameter is incorrect" });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Listeners couldn't be read: The parameter is incorrect", result.Evidence);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new EP06_HostFirewallCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.Contains("[High-Risk Listeners (IP Helper API)]", result.Evidence);
        Assert.DoesNotContain("Listener read failed", result.Evidence);
    }

    private static List<Listener> DefaultWorkstationListeners() =>
    [
        new("TCP", "0.0.0.0", 135),
        new("TCP", "::", 135),
        new("TCP", "192.168.1.20", 139),
        new("TCP", "0.0.0.0", 445),
        new("TCP", "::", 445),
        new("TCP", "0.0.0.0", 5985),
        new("TCP", "0.0.0.0", 49664),
        new("TCP", "127.0.0.1", 5939),
    ];

    private static IReadOnlyList<FirewallProfileSnapshot> HealthyProfiles() =>
    [
        Profile("Domain"),
        Profile("Private"),
        Profile("Public")
    ];

    private static FirewallProfileSnapshot Profile(
        string name,
        bool? enabled = true,
        FirewallDefaultAction inbound = FirewallDefaultAction.Block,
        FirewallDefaultAction outbound = FirewallDefaultAction.Allow,
        bool? logDropped = true,
        ulong? logMaxSizeKb = 4096) =>
        new(name, enabled, inbound, outbound, logDropped, logMaxSizeKb, "WMI");

    private static PortSnapshot NoHighRiskListeners(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return new PortSnapshot { Listeners = [new("TCP", "127.0.0.1", 49712)] };
    }

    // EP06 no longer runs netstat; only the netsh profile fallback runs a command.
    private static string NoCommands(string fileName, string arguments, CancellationToken ct) =>
        throw new InvalidOperationException($"Unexpected command: {fileName} {arguments}");

    private static string NetshProfileOutput(string fileName, string arguments, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        return fileName switch
        {
            "netsh" => """
                Domain Profile Settings:
                ----------------------------------------------------------------------
                State OFF
                Firewall Policy BlockInbound,AllowOutbound
                LogDroppedConnections Enable
                LogMaxFileSize 4096

                Private Profile Settings:
                ----------------------------------------------------------------------
                State     ON
                Firewall Policy     BlockInbound,AllowOutbound
                LogDroppedConnections Enable
                LogMaxFileSize 4096

                Public Profile Settings:
                ----------------------------------------------------------------------
                State                                 ON
                Firewall Policy                       BlockInbound,AllowOutbound
                LogDroppedConnections                 Enable
                LogMaxFileSize                        4096
                """,
            _ => throw new InvalidOperationException(fileName)
        };
    }
}

using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class EP06_HostFirewallCheckTests
{
    [Fact]
    public async Task ExecuteAsync_Passes_When_Wmi_Profiles_Are_Healthy()
    {
        var check = new EP06_HostFirewallCheck(HealthyProfiles, NoListeningHighRiskPorts);

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
            NoListeningHighRiskPorts);

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
            NoListeningHighRiskPorts);

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
            NoListeningHighRiskPorts);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("dropped-connection logging is disabled", result.Findings);
    }

    [Fact]
    public async Task ExecuteAsync_Uses_Netsh_Fallback_With_Flexible_State_Spacing()
    {
        var check = new EP06_HostFirewallCheck(
            () => throw new InvalidOperationException("CIM unavailable"),
            NetshProfileOutput);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Firewall profile 'Domain' is DISABLED", result.Findings);
        Assert.Contains("[netsh] Domain", result.Evidence);
    }

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

    private static string NoListeningHighRiskPorts(string fileName, string arguments, CancellationToken ct)
    {
        Assert.Equal("netstat", fileName);
        Assert.Equal("-an -p TCP", arguments);
        ct.ThrowIfCancellationRequested();
        return """
            Active Connections

              Proto  Local Address          Foreign Address        State
              TCP    127.0.0.1:49712        127.0.0.1:49713        ESTABLISHED
            """;
    }

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
            "netstat" => NoListeningHighRiskPorts(fileName, arguments, ct),
            _ => throw new InvalidOperationException(fileName)
        };
    }
}

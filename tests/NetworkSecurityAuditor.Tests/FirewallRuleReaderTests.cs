using NetworkSecurityAuditor.Checks.NetworkPerimeter;

namespace NetworkSecurityAuditor.Tests;

public class FirewallRuleReaderTests
{
    [Fact]
    public void Snapshot_Does_Not_Treat_Restricted_Filters_As_AnyAny()
    {
        var rule = new FirewallRuleSnapshot(
            "{restricted}",
            "Restricted HTTPS",
            string.Empty,
            Direction: 1,
            Action: 2,
            Protocol: "TCP",
            LocalPorts: ["443"],
            RemotePorts: [],
            RemoteAddresses: ["LocalSubnet"]);

        Assert.True(rule.IsInbound);
        Assert.True(rule.IsAllow);
        Assert.False(rule.HasAnyLocalPort);
        Assert.False(rule.HasAnyRemoteAddress);
    }

    [Fact]
    public void Snapshot_Treats_Empty_Wmi_Filter_Arrays_As_Any()
    {
        var rule = new FirewallRuleSnapshot(
            "{any}",
            "Any inbound",
            string.Empty,
            Direction: 1,
            Action: 2,
            Protocol: "Any",
            LocalPorts: [],
            RemotePorts: [],
            RemoteAddresses: []);

        Assert.True(rule.HasAnyLocalPort);
        Assert.True(rule.HasAnyRemotePort);
        Assert.True(rule.HasAnyRemoteAddress);
        Assert.Equal("Any", FirewallRuleReader.FormatValues(rule.LocalPorts));
    }

    [Fact]
    public void Snapshot_Treats_Wildcard_Remote_Networks_As_Any()
    {
        Assert.True(FirewallRuleReader.IsAnyValue(["Any"]));
        Assert.True(FirewallRuleReader.IsAnyValue(["*"]));
        Assert.True(FirewallRuleReader.IsAnyValue(["0.0.0.0/0"]));
        Assert.True(FirewallRuleReader.IsAnyValue(["::/0"]));
        Assert.False(FirewallRuleReader.IsAnyValue(["LocalSubnet"]));
        Assert.False(FirewallRuleReader.IsAnyValue(["10.0.0.0/8"]));
    }
}

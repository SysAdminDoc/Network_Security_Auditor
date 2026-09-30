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
    public void Application_Scope_Covers_Program_Package_Service_And_Owner()
    {
        FirewallRuleSnapshot Rule(string? program = null, string? package = null, string? service = null, string? owner = null) =>
            new("{r}", "r", string.Empty, 1, 2, "Any", [], [], [], Profiles: 4, Program: program, Package: package, Service: service, Owner: owner);

        Assert.True(Rule().HasNoApplicationScope);
        Assert.True(Rule(program: "Any", package: "", service: "Any", owner: "").HasNoApplicationScope);
        Assert.False(Rule(program: @"C:\Windows\System32\svchost.exe").HasNoApplicationScope);
        Assert.False(Rule(package: "S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742").HasNoApplicationScope);
        Assert.False(Rule(service: "TermService").HasNoApplicationScope);
        Assert.False(Rule(owner: "S-1-5-21-1-2-3-1001").HasNoApplicationScope);
    }

    // Guards against WQL naming a property the NetSecurity classes don't have ("Invalid query"),
    // which broke every firewall check. Reading port filters needs elevation, so access denied is fine.
    [Theory]
    [InlineData(null)]
    [InlineData(FirewallRuleReader.ActiveStore)]
    public void Every_Reader_Query_Is_Valid_Wql_For_The_NetSecurity_Classes(string? policyStore)
    {
        if (!OperatingSystem.IsWindows())
            return;

        foreach (var query in FirewallRuleReader.Queries)
        {
            using var searcher = FirewallRuleReader.CreateSearcher(query, policyStore);
            try
            {
                using var results = searcher.Get();
                foreach (var item in results)
                    item.Dispose();
            }
            catch (System.Management.ManagementException ex) when (ex.ErrorCode == System.Management.ManagementStatus.AccessDenied)
            {
            }
        }
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

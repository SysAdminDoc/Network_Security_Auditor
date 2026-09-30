namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;

public sealed class NP06TempRulesCheckTests
{
    private static FirewallRuleSnapshot Rule(string name, string description = "") =>
        new($"{{{name}}}", name, description, Direction: 1, Action: 2, Protocol: null, LocalPorts: [], RemotePorts: [], RemoteAddresses: []);

    [Fact]
    public async Task Reads_The_Active_Store_So_A_Group_Policy_Temp_Rule_Is_Seen()
    {
        var check = new NP06_TempRulesCheck((_, store) => store == FirewallRuleReader.ActiveStore
            ? [Rule("Core Networking - DNS (UDP-Out)"), Rule("Vendor access - TEMP until go-live")]
            : [Rule("Core Networking - DNS (UDP-Out)")]);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Scanned 2 enabled firewall rules", result.Findings);
        Assert.Contains("Vendor access - TEMP until go-live", result.Findings);
        Assert.Contains("active store", result.Evidence);
    }

    // Names are all NP06 needs, and the rules (unlike their filters) are readable without elevation,
    // so a standard user reads the active store directly instead of falling back to netsh.
    [Fact]
    public async Task Live_Host_Reads_The_Active_Store_Without_Elevation()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new NP06_TempRulesCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.Contains("[Firewall Rule Staleness Analysis - active store", result.Evidence);
        Assert.DoesNotContain("WMI error", result.Evidence);
        Assert.DoesNotContain("Parsed from netsh", result.Evidence);
    }
}

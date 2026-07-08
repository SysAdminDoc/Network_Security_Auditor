using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CF02_EgressTestCheckTests
{
    [Fact]
    public async Task ExecuteAsync_Returns_NA_When_Control_Port_Is_Unreachable()
    {
        var check = new CF02_EgressTestCheck((_, _, _) => false);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.NA, result.Status);
        Assert.Contains("control port", result.Findings, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Control connection failed", result.Evidence);
    }

    [Fact]
    public async Task ExecuteAsync_Passes_When_Control_Succeeds_And_High_Risk_Ports_Are_Blocked()
    {
        var check = new CF02_EgressTestCheck((_, port, _) => port == 80);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("9 ports tested, 0 open, 9 blocked", result.Findings);
        Assert.Contains("Control connection succeeded", result.Evidence);
    }

    [Fact]
    public async Task ExecuteAsync_Flags_Reachable_High_Risk_Ports()
    {
        var openPorts = new HashSet<int> { 80, 25, 445, 3389, 4444 };
        var check = new CF02_EgressTestCheck((_, port, _) => openPorts.Contains(port));

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("4 high-risk port(s) are reachable outbound", result.Findings);
        Assert.Contains("OPEN: portquiz.net:445", result.Evidence);
    }
}

namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.NetworkPerimeter;

public sealed class NP03VpnCheckTests
{
    [Fact]
    public void AssessSplitTunnelRoutes_Does_Not_Treat_Multiple_Default_Routes_As_Split_Tunnel()
    {
        const string routeOutput = """
            Network Destination        Netmask          Gateway       Interface  Metric
                      0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
                      0.0.0.0          0.0.0.0      10.10.10.1     10.10.10.20     35
            """;

        var assessment = NP03_VpnCheck.AssessSplitTunnelRoutes(routeOutput);

        Assert.Equal(2, assessment.DefaultRouteCount);
        Assert.True(assessment.HasMultipleDefaultRoutes);
        Assert.False(assessment.IsConfirmedSplitTunnel);
    }

    [Fact]
    public void AssessSplitTunnelRoutes_Counts_Single_Default_Route()
    {
        const string routeOutput = """
            Network Destination        Netmask          Gateway       Interface  Metric
                      0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
            """;

        var assessment = NP03_VpnCheck.AssessSplitTunnelRoutes(routeOutput);

        Assert.Equal(1, assessment.DefaultRouteCount);
        Assert.False(assessment.HasMultipleDefaultRoutes);
        Assert.False(assessment.IsConfirmedSplitTunnel);
    }
}

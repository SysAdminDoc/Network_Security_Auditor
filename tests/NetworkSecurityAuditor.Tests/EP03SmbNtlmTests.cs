namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.EndpointSecurity;

public sealed class EP03SmbNtlmTests
{
    [Fact]
    public void AssessNetBios_Does_Not_Fail_When_NodeType_Is_Not_PNode_But_Adapters_Are_Disabled()
    {
        var assessment = EP03_SmbNtlmCheck.AssessNetBios(nodeType: 8, adapterOptions: [2, 2]);

        Assert.False(assessment.HasFailure);
        Assert.True(assessment.HasStrongDisableSignal);
    }

    [Fact]
    public void AssessNetBios_Does_Not_Treat_Dhcp_Default_As_Explicitly_Enabled()
    {
        var assessment = EP03_SmbNtlmCheck.AssessNetBios(nodeType: -1, adapterOptions: [0]);

        Assert.False(assessment.HasFailure);
        Assert.True(assessment.HasDhcpDefaultInterface);
        Assert.False(assessment.HasStrongDisableSignal);
    }

    [Fact]
    public void AssessNetBios_Fails_Only_When_An_Interface_Is_Explicitly_Enabled()
    {
        var assessment = EP03_SmbNtlmCheck.AssessNetBios(nodeType: 2, adapterOptions: [2, 1, 0]);

        Assert.True(assessment.HasFailure);
        Assert.True(assessment.HasStrongDisableSignal);
    }
}

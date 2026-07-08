namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.EndpointSecurity;

public sealed class EP01AvEdrTests
{
    [Theory]
    [InlineData(0x041000u)]
    [InlineData(0x061100u)]
    public void DecodeSecurityCenterProductState_Recognizes_Enabled_And_UpToDate_States(uint rawState)
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(rawState);

        Assert.True(decoded.Enabled);
        Assert.True(decoded.SignaturesUpToDate);
    }

    [Fact]
    public void DecodeSecurityCenterProductState_Uses_Full_Signature_Status_Byte()
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(0x041001u);

        Assert.True(decoded.Enabled);
        Assert.Equal(0x01, decoded.SignatureStatus);
        Assert.False(decoded.SignaturesUpToDate);
    }

    [Fact]
    public void DecodeSecurityCenterProductState_Does_Not_Treat_Unknown_Scanner_State_As_Enabled()
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(0x040000u);

        Assert.False(decoded.Enabled);
        Assert.True(decoded.SignaturesUpToDate);
    }
}

using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Checks.NetworkArchitecture;

namespace NetworkSecurityAuditor.Tests;

public class CheckParsingRegressionTests
{
    [Theory]
    [InlineData("Open", "Insecure")]
    [InlineData("WEP", "Insecure")]
    [InlineData("WPA-Personal", "Insecure")]
    [InlineData("WPA2-Personal", "Secure")]
    [InlineData("WPA3-Enterprise", "Secure")]
    [InlineData("WPA2PSK", "Secure")]
    [InlineData("WPA3SAE", "Secure")]
    [InlineData("Enhanced Open", "Secure")]
    [InlineData("Vendor-Proprietary", "Unknown")]
    public void Wireless_Authentication_Classification_Uses_Normalized_Exact_Values(
        string authentication,
        string expected)
    {
        Assert.Equal(expected, NA03_WirelessCheck.AssessAuthentication(authentication).ToString());
    }

    [Fact]
    public void Wireless_Profile_Xml_Parser_Reads_Invariant_Exported_Profile()
    {
        const string xml = """
            <?xml version="1.0"?>
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
              <name>Corp-WiFi</name>
              <connectionMode>auto</connectionMode>
              <MSM>
                <security>
                  <authEncryption>
                    <authentication>WPA2PSK</authentication>
                    <encryption>AES</encryption>
                    <useOneX>false</useOneX>
                  </authEncryption>
                </security>
              </MSM>
            </WLANProfile>
            """;

        var details = NA03_WirelessCheck.ParseExportedProfileXml(xml);

        Assert.NotNull(details);
        Assert.Equal("Corp-WiFi", details.Name);
        Assert.Equal("WPA2PSK", details.Authentication);
        Assert.Equal("AES", details.Cipher);
        Assert.Equal("auto", details.ConnectionMode);
    }

    [Fact]
    public void Password_Policy_Interval_Conversion_Handles_Long_MinValue_Sentinel()
    {
        var days = IA05_PasswordPolicyCheck.ConvertDirectoryIntervalToWholeUnits(long.MinValue, TimeSpan.TicksPerDay);

        Assert.Equal(0, days);
    }

    [Fact]
    public void Password_Policy_Interval_Conversion_Handles_Negative_ActiveDirectory_Intervals()
    {
        var interval = -90L * TimeSpan.TicksPerDay;

        var days = IA05_PasswordPolicyCheck.ConvertDirectoryIntervalToWholeUnits(interval, TimeSpan.TicksPerDay);

        Assert.Equal(90, days);
    }
}

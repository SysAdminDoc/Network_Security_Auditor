namespace NetworkSecurityAuditor.Tests;

using System.Globalization;
using NetworkSecurityAuditor.Checks.EndpointSecurity;

public sealed class EP04PatchComplianceTests
{
    [Fact]
    public void ParseInstalledOn_Uses_Invariant_Culture_For_US_Wmi_Dates()
    {
        CultureInfo originalCulture = CultureInfo.CurrentCulture;
        CultureInfo originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("fr-FR");

            var parsed = EP04_PatchComplianceCheck.ParseInstalledOn("1/31/2026");

            Assert.Equal(new DateTime(2026, 1, 31), parsed);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public void ParseInstalledOn_Handles_Hex_FileTime_Values()
    {
        var expected = new DateTime(2026, 1, 31, 0, 0, 0, DateTimeKind.Utc);
        string raw = "0x" + expected.ToFileTimeUtc().ToString("x", CultureInfo.InvariantCulture);

        var parsed = EP04_PatchComplianceCheck.ParseInstalledOn(raw);

        Assert.Equal(expected.ToLocalTime().Date, parsed);
    }

    [Fact]
    public void ParseInstalledOn_Handles_Compact_Wmi_Date_Values()
    {
        var parsed = EP04_PatchComplianceCheck.ParseInstalledOn("20260131");

        Assert.Equal(new DateTime(2026, 1, 31), parsed);
    }
}

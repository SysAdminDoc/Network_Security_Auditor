using System.Globalization;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CheckResultTests
{
    [Fact]
    public void Factory_Evidence_Timestamps_Use_Invariant_Utc_Format()
    {
        var originalCulture = Thread.CurrentThread.CurrentCulture;
        var originalUiCulture = Thread.CurrentThread.CurrentUICulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("ar-SA");

            var error = CheckResult.FromError("EP01", new InvalidOperationException("boom"));
            var notImplemented = CheckResult.NotImplemented("EP02");

            Assert.Matches(@"^Error @ \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$", error.Evidence);
            Assert.Matches(@"^Not implemented @ \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$", notImplemented.Evidence);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = originalCulture;
            Thread.CurrentThread.CurrentUICulture = originalUiCulture;
        }
    }
}

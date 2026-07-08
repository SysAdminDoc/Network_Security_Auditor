using NetworkSecurityAuditor.Checks.IdentityAccess;

namespace NetworkSecurityAuditor.Tests;

public class ActiveDirectoryValueConverterTests
{
    [Fact]
    public void GetLargeIntegerValue_Returns_Long_Values()
    {
        var fileTime = new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

        Assert.Equal(fileTime, ActiveDirectoryValueConverter.GetLargeIntegerValue(fileTime));
    }

    [Fact]
    public void GetLargeIntegerValue_Combines_Com_High_And_Low_Parts()
    {
        var expected = new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
        var largeInteger = new FakeLargeInteger
        {
            HighPart = (int)(expected >> 32),
            LowPart = unchecked((int)(expected & uint.MaxValue))
        };

        Assert.Equal(expected, ActiveDirectoryValueConverter.GetLargeIntegerValue(largeInteger));
        Assert.Equal(DateTime.FromFileTimeUtc(expected), ActiveDirectoryValueConverter.GetFileTimeUtc(largeInteger));
    }

    [Fact]
    public void GetFileTimeUtc_Returns_Null_For_Invalid_Values()
    {
        Assert.Null(ActiveDirectoryValueConverter.GetFileTimeUtc(null));
        Assert.Null(ActiveDirectoryValueConverter.GetFileTimeUtc(new object()));
        Assert.Null(ActiveDirectoryValueConverter.GetFileTimeUtc(-1L));
    }

    private sealed class FakeLargeInteger
    {
        public int HighPart { get; init; }
        public int LowPart { get; init; }
    }
}

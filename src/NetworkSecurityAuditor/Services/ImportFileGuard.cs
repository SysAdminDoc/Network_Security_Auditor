using System.IO;

namespace NetworkSecurityAuditor.Services;

internal static class ImportFileGuard
{
    public const long MaxAuditStateBytes = 10 * 1_024 * 1_024;
    public const long MaxWaiverStoreBytes = 5 * 1_024 * 1_024;
    public const long MaxDashboardFileBytes = 10 * 1_024 * 1_024;
    public const long MaxDashboardTotalBytes = 100 * 1_024 * 1_024;
    public const int MaxDashboardFiles = 5_000;

    public static void EnsureWithinSizeLimit(string path, long maxBytes, string description)
    {
        var length = new FileInfo(path).Length;
        if (length > maxBytes)
        {
            throw new InvalidDataException(
                $"{description} file is {length:N0} bytes; maximum supported size is {maxBytes:N0} bytes.");
        }
    }
}

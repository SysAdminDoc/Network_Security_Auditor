using System.IO;

namespace NetworkSecurityAuditor.Services;

internal static class ImportFileGuard
{
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

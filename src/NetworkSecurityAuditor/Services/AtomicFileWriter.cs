using System.IO;
using System.Text;

namespace NetworkSecurityAuditor.Services;

public static class AtomicFileWriter
{
    public static async Task WriteAllTextAsync(
        string path,
        string contents,
        CancellationToken ct = default)
    {
        var targetPath = PrepareTarget(path);
        var tempPath = CreateTempPath(targetPath);

        try
        {
            await File.WriteAllTextAsync(tempPath, contents, Encoding.UTF8, ct);
            File.Move(tempPath, targetPath, overwrite: true);
        }
        finally
        {
            DeleteTempFile(tempPath);
        }
    }

    public static void WriteAllText(string path, string contents)
    {
        var targetPath = PrepareTarget(path);
        var tempPath = CreateTempPath(targetPath);

        try
        {
            File.WriteAllText(tempPath, contents, Encoding.UTF8);
            File.Move(tempPath, targetPath, overwrite: true);
        }
        finally
        {
            DeleteTempFile(tempPath);
        }
    }

    private static string PrepareTarget(string path)
    {
        var targetPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        return targetPath;
    }

    private static string CreateTempPath(string targetPath)
    {
        var directory = Path.GetDirectoryName(targetPath);
        var fileName = Path.GetFileName(targetPath);
        var tempName = $".{fileName}.{Guid.NewGuid():N}.tmp";
        return string.IsNullOrWhiteSpace(directory)
            ? tempName
            : Path.Combine(directory, tempName);
    }

    private static void DeleteTempFile(string tempPath)
    {
        try
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
        }
        catch
        {
            // Best effort cleanup only; the target file has either moved or the caller will receive the original write error.
        }
    }
}

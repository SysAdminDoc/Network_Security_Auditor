using System.IO;
using System.Text;

namespace NetworkSecurityAuditor.Services;

public static class CrashLogWriter
{
    public static string Write(Exception exception, string source)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var directory = string.IsNullOrWhiteSpace(localAppData)
            ? Path.GetTempPath()
            : Path.Combine(localAppData, "NetworkSecurityAuditor");

        return Write(exception, source, directory);
    }

    internal static string Write(Exception exception, string source, string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "crash.log");
            File.AppendAllText(path, Format(exception, source), Encoding.UTF8);
            return path;
        }
        catch
        {
            var fallback = Path.Combine(Path.GetTempPath(), "NetworkSecurityAuditor-crash.log");
            File.AppendAllText(fallback, Format(exception, source), Encoding.UTF8);
            return fallback;
        }
    }

    private static string Format(Exception exception, string source)
    {
        var sb = new StringBuilder();
        sb.AppendLine("==== Network Security Auditor Crash ====");
        sb.AppendLine($"UTC: {DateTime.UtcNow:O}");
        sb.AppendLine($"Source: {source}");
        sb.AppendLine(exception.ToString());
        sb.AppendLine();
        return sb.ToString();
    }
}

using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkSecurityAuditor.Services;

public static class CrashLogWriter
{
    private const int MaxLogBytes = 256 * 1024;
    private const int MaxArchiveCount = 3;
    private static readonly object SyncRoot = new();

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
        var formatted = Format(exception, source);
        try
        {
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "crash.log");
            lock (SyncRoot)
            {
                if (!TryWithInterprocessLock(path, () => AppendBounded(path, formatted)))
                    AppendBounded(path, formatted);
            }
            return path;
        }
        catch
        {
            var fallback = Path.Combine(Path.GetTempPath(), "NetworkSecurityAuditor-crash.log");
            try
            {
                lock (SyncRoot)
                {
                    if (!TryWithInterprocessLock(fallback, () => AppendBounded(fallback, formatted)))
                        AppendBounded(fallback, formatted);
                }
            }
            catch
            {
                // Crash logging must never replace the original application failure.
            }
            return fallback;
        }
    }

    private static string Format(Exception exception, string source)
    {
        var sb = new StringBuilder();
        sb.AppendLine("==== Network Security Auditor Crash ====");
        sb.AppendLine($"UTC: {DateTime.UtcNow:O}");
        sb.AppendLine($"Source: {Redact(source)}");
        sb.AppendLine(Redact(exception.ToString()));
        sb.AppendLine();
        return sb.ToString();
    }

    private static void AppendBounded(string path, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        if (bytes.Length > MaxLogBytes)
            bytes = bytes[^MaxLogBytes..];

        var currentLength = File.Exists(path) ? new FileInfo(path).Length : 0;
        if (currentLength + bytes.Length > MaxLogBytes)
        {
            for (var index = MaxArchiveCount - 1; index >= 1; index--)
            {
                var older = $"{path}.{index}";
                var newer = $"{path}.{index + 1}";
                if (File.Exists(older))
                    File.Move(older, newer, overwrite: true);
            }

            if (File.Exists(path))
                File.Move(path, $"{path}.1", overwrite: true);
        }

        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static bool TryWithInterprocessLock(string path, Action action)
    {
        var lockPath = $"{path}.lock";
        try
        {
            using var lockStream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            for (var attempt = 0; attempt < 10; attempt++)
            {
                try
                {
                    lockStream.Lock(0, 1);
                }
                catch (IOException) when (attempt < 9)
                {
                    Thread.Sleep(10);
                    continue;
                }

                try { action(); }
                finally { lockStream.Unlock(0, 1); }
                return true;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return false;
    }

    private static string Redact(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        var redacted = Regex.Replace(
            value,
            @"(?ix)(?<prefix>\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|client[_-]?assertion|api[_-]?key|apikey|password|secret|private[_-]?key|authorization)\b\s*[:=]\s*)(?<value>[^\s,;""']+)",
            "${prefix}[REDACTED]",
            RegexOptions.CultureInvariant);
        redacted = Regex.Replace(redacted, @"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", RegexOptions.CultureInvariant);
        redacted = Regex.Replace(redacted, @"(?i)(?:[A-Z]:\\|\\\\)[^\r\n""']+", "[PATH-REDACTED]", RegexOptions.CultureInvariant);
        redacted = Regex.Replace(redacted, @"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[IDENTITY-REDACTED]", RegexOptions.CultureInvariant);
        return redacted;
    }
}

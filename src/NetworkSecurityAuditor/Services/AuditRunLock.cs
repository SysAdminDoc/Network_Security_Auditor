using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSecurityAuditor.Services;

public sealed class AuditRunLock : IDisposable
{
    private const int SchemaVersion = 1;
    private static readonly TimeSpan DefaultStaleAfter = TimeSpan.FromMinutes(15);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private readonly FileStream _stream;
    private bool _disposed;

    private AuditRunLock(FileStream stream, string path)
    {
        _stream = stream;
        LockPath = path;
    }

    public string LockPath { get; }
    public string RunId { get; private set; } = string.Empty;

    public static AuditRunLock? TryAcquire(
        string outputDirectory,
        string client,
        string target,
        string? historyIdentity = null,
        TimeSpan? staleAfter = null,
        DateTimeOffset? now = null,
        int? processId = null)
    {
        if (string.IsNullOrWhiteSpace(outputDirectory))
            throw new ArgumentException("An output directory is required.", nameof(outputDirectory));

        var directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        var identity = BuildIdentity(directory, client, target, historyIdentity);
        var lockPath = GetLockPath(directory, identity);
        var cutoff = (now ?? DateTimeOffset.UtcNow) - (staleAfter ?? DefaultStaleAfter);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var stream = new FileStream(lockPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
                var runLock = new AuditRunLock(stream, lockPath)
                {
                    RunId = Guid.NewGuid().ToString("N")
                };
                var metadata = new AuditRunLockMetadata
                {
                    SchemaVersion = SchemaVersion,
                    RunId = runLock.RunId,
                    ToolVersion = VersionInfo.Version,
                    ProcessId = processId ?? Environment.ProcessId,
                    StartedAtUtc = (now ?? DateTimeOffset.UtcNow).ToUniversalTime(),
                    Identity = identity,
                    Client = client ?? string.Empty,
                    Target = target ?? string.Empty,
                    OutputDirectory = directory
                };
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(metadata, JsonOptions));
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
                return runLock;
            }
            catch (IOException)
            {
                if (attempt > 0 || !CanRecoverStaleLock(lockPath, cutoff))
                    return null;

                try
                {
                    File.Delete(lockPath);
                }
                catch (IOException)
                {
                    return null;
                }
                catch (UnauthorizedAccessException)
                {
                    return null;
                }
            }
        }

        return null;
    }

    internal static string BuildIdentity(string outputDirectory, string client, string target, string? historyIdentity)
    {
        return string.Join("|", Normalize(outputDirectory), Normalize(client), Normalize(target), Normalize(historyIdentity ?? string.Empty));
    }

    internal static string GetLockPath(string outputDirectory, string identity)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
        return Path.Combine(outputDirectory, $".network-security-auditor-{hash[..32]}.run.lock");
    }

    private static bool CanRecoverStaleLock(string lockPath, DateTimeOffset cutoff)
    {
        try
        {
            var info = new FileInfo(lockPath);
            if (!info.Exists || info.LastWriteTimeUtc > cutoff.UtcDateTime)
                return false;

            using var stream = new FileStream(lockPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var metadata = JsonSerializer.Deserialize<AuditRunLockMetadata>(stream, JsonOptions);
            if (metadata is null || metadata.SchemaVersion != SchemaVersion || metadata.ProcessId <= 0)
                return false;

            try
            {
                using var process = Process.GetProcessById(metadata.ProcessId);
                if (process.HasExited)
                    return true;

                try
                {
                    // A live process that started after the recorded owner cannot own this lock;
                    // the PID was reused after the original audit crashed.
                    var processStartedAtUtc = process.StartTime.ToUniversalTime();
                    return processStartedAtUtc > metadata.StartedAtUtc.UtcDateTime.AddMinutes(1);
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // If ownership cannot be proven, preserve the lock rather than overlap scans.
                    return false;
                }
            }
            catch (ArgumentException)
            {
                return true;
            }
            catch (InvalidOperationException)
            {
                return true;
            }
        }
        catch (IOException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Normalize(string value) =>
        value.Trim().Replace('\\', '/').ToUpperInvariant();

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        try
        {
            _stream.Dispose();
        }
        finally
        {
            try
            {
                File.Delete(LockPath);
            }
            catch (IOException)
            {
                // A locked artifact is safer to recover on the next run than to fail a completed audit.
            }
            catch (UnauthorizedAccessException)
            {
                // See the IOException comment above.
            }
        }
    }
}

internal sealed class AuditRunLockMetadata
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("run_id")]
    public string RunId { get; init; } = string.Empty;

    [JsonPropertyName("tool_version")]
    public string ToolVersion { get; init; } = string.Empty;

    [JsonPropertyName("process_id")]
    public int ProcessId { get; init; }

    [JsonPropertyName("started_at_utc")]
    public DateTimeOffset StartedAtUtc { get; init; }

    [JsonPropertyName("identity")]
    public string Identity { get; init; } = string.Empty;

    [JsonPropertyName("client")]
    public string Client { get; init; } = string.Empty;

    [JsonPropertyName("target")]
    public string Target { get; init; } = string.Empty;

    [JsonPropertyName("output_directory")]
    public string OutputDirectory { get; init; } = string.Empty;
}

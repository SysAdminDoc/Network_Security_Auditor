using System.Diagnostics;
using System.Text.Json;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public sealed class AuditRunLockTests
{
    [Fact]
    public void Acquire_Records_Owner_And_Blocks_Only_The_Same_Normalized_Identity()
    {
        var directory = CreateTestDirectory();
        var now = new DateTimeOffset(2026, 8, 12, 12, 0, 0, TimeSpan.Zero);

        try
        {
            using var first = AuditRunLock.TryAcquire(
                directory,
                "Client A",
                "Host A",
                @"history\client-a",
                now: now,
                processId: Environment.ProcessId);

            Assert.NotNull(first);
            Assert.True(File.Exists(first.LockPath));

            using var metadataStream = new FileStream(
                first.LockPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);
            using var metadata = JsonDocument.Parse(metadataStream);
            var root = metadata.RootElement;
            Assert.Equal(1, root.GetProperty("schema_version").GetInt32());
            Assert.Equal(first.RunId, root.GetProperty("run_id").GetString());
            Assert.Equal(VersionInfo.Version, root.GetProperty("tool_version").GetString());
            Assert.Equal(Environment.ProcessId, root.GetProperty("process_id").GetInt32());
            Assert.Equal("Client A", root.GetProperty("client").GetString());
            Assert.Equal("Host A", root.GetProperty("target").GetString());
            Assert.Equal(Path.GetFullPath(directory), root.GetProperty("output_directory").GetString());

            using var duplicate = AuditRunLock.TryAcquire(
                directory,
                " client a ",
                "host a",
                "history/client-a",
                now: now.AddMinutes(1));
            Assert.Null(duplicate);

            using var unrelatedTarget = AuditRunLock.TryAcquire(
                directory,
                "Client A",
                "Host B",
                @"history\client-a",
                now: now.AddMinutes(1));
            Assert.NotNull(unrelatedTarget);
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    [Fact]
    public void Dispose_Releases_Completed_Or_Canceled_Run()
    {
        var directory = CreateTestDirectory();

        try
        {
            var first = AuditRunLock.TryAcquire(directory, "Client", "Host");
            Assert.NotNull(first);
            var lockPath = first.LockPath;

            first.Dispose();

            Assert.False(File.Exists(lockPath));
            using var next = AuditRunLock.TryAcquire(directory, "Client", "Host");
            Assert.NotNull(next);
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    [Fact]
    public void Acquire_Recovers_Stale_Crashed_Owner_But_Preserves_Live_Owner()
    {
        var directory = CreateTestDirectory();
        var now = DateTimeOffset.UtcNow;

        try
        {
            WriteUnlockedLock(directory, "crashed", "host-a", int.MaxValue, now.AddHours(-1));
            using var recovered = AuditRunLock.TryAcquire(
                directory,
                "crashed",
                "host-a",
                staleAfter: TimeSpan.FromMinutes(15),
                now: now);
            Assert.NotNull(recovered);

            var currentProcessStartedAt = new DateTimeOffset(Process.GetCurrentProcess().StartTime.ToUniversalTime());
            WriteUnlockedLock(directory, "live", "host-b", Environment.ProcessId, currentProcessStartedAt);
            using var blocked = AuditRunLock.TryAcquire(
                directory,
                "live",
                "host-b",
                staleAfter: TimeSpan.FromMinutes(15),
                now: now);
            Assert.Null(blocked);
        }
        finally
        {
            DeleteTestDirectory(directory);
        }
    }

    private static void WriteUnlockedLock(
        string directory,
        string client,
        string target,
        int processId,
        DateTimeOffset startedAtUtc)
    {
        var identity = AuditRunLock.BuildIdentity(directory, client, target, null);
        var lockPath = AuditRunLock.GetLockPath(directory, identity);
        var metadata = new AuditRunLockMetadata
        {
            SchemaVersion = 1,
            RunId = Guid.NewGuid().ToString("N"),
            ToolVersion = VersionInfo.Version,
            ProcessId = processId,
            StartedAtUtc = startedAtUtc,
            Identity = identity,
            Client = client,
            Target = target,
            OutputDirectory = directory
        };

        File.WriteAllText(lockPath, JsonSerializer.Serialize(metadata));
        File.SetLastWriteTimeUtc(lockPath, DateTime.UtcNow.AddHours(-1));
    }

    private static string CreateTestDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nsa-run-lock-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteTestDirectory(string directory)
    {
        if (Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }
}

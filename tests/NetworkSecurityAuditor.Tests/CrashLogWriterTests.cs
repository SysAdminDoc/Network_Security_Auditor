using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class CrashLogWriterTests
{
    [Fact]
    public void Write_Creates_Crash_Log_With_Source_And_Exception()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"nsa-crash-test-{Guid.NewGuid():N}");
        try
        {
            var path = CrashLogWriter.Write(
                new InvalidOperationException("bad audit state"),
                "LoadStateAsync",
                directory);

            var content = File.ReadAllText(path);
            Assert.Equal(Path.Combine(directory, "crash.log"), path);
            Assert.Contains("Network Security Auditor Crash", content);
            Assert.Contains("LoadStateAsync", content);
            Assert.Contains("bad audit state", content);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Write_Redacts_Sensitive_Exception_Data_And_Rotates_Bounded_Logs()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"nsa-crash-bounded-{Guid.NewGuid():N}");
        try
        {
            for (var index = 0; index < 400; index++)
            {
                CrashLogWriter.Write(
                    new InvalidOperationException($"api_key=super-secret-{index} path=C:\\Users\\Auditor\\input-{index}.json user=auditor@example.com"),
                    "ImportState",
                    directory);
            }
            CrashLogWriter.Write(new InvalidOperationException("contact auditor@example.com"), "ImportState", directory);

            var logFiles = Directory.GetFiles(directory, "crash.log*");
            Assert.Contains(logFiles, path => path.EndsWith("crash.log", StringComparison.Ordinal));
            Assert.All(logFiles.Where(path => !path.EndsWith(".lock", StringComparison.Ordinal)), path =>
                Assert.True(new FileInfo(path).Length <= 256 * 1024));

            var content = string.Join(Environment.NewLine, logFiles.Select(File.ReadAllText));
            Assert.DoesNotContain("super-secret-", content, StringComparison.Ordinal);
            Assert.DoesNotContain("C:\\Users\\Auditor", content, StringComparison.Ordinal);
            Assert.DoesNotContain("auditor@example.com", content, StringComparison.Ordinal);
            Assert.Contains("[REDACTED]", content, StringComparison.Ordinal);
            Assert.Contains("[PATH-REDACTED]", content, StringComparison.Ordinal);
            Assert.Contains("[IDENTITY-REDACTED]", content, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }
}

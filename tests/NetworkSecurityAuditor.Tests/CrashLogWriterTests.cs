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
}

namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Services;

public sealed class CommandRunnerTests
{
    [Fact]
    public void Run_Drains_Stdout_And_Stderr_Concurrently()
    {
        string script = "for ($i = 0; $i -lt 20000; $i++) { [Console]::Error.WriteLine('err' + $i) }; [Console]::Out.WriteLine('done')";

        var result = CommandRunner.Run(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
            TimeSpan.FromSeconds(15),
            CancellationToken.None);

        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("done", result.StandardOutput);
        Assert.Contains("err19999", result.StandardError);
    }

    [Fact]
    public void Run_Terminates_Process_When_Timeout_Expires()
    {
        var result = CommandRunner.Run(
            "powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command \"Start-Sleep -Seconds 30\"",
            TimeSpan.FromMilliseconds(500),
            CancellationToken.None);

        Assert.True(result.TimedOut);
        Assert.Null(result.ExitCode);
    }
}

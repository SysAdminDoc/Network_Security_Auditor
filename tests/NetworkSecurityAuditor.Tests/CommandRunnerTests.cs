namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Services;

[Collection(NonParallelTestCollection.Name)]
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

    [Fact]
    public void Firewall_Netsh_Fallbacks_Use_Shared_CommandRunner()
    {
        var root = FindRepoRoot();
        var files = new[]
        {
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Checks", "NetworkPerimeter", "NP01_FirewallRulesCheck.cs"),
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Checks", "NetworkPerimeter", "NP05_EgressFilteringCheck.cs"),
            Path.Combine(root, "src", "NetworkSecurityAuditor", "Checks", "NetworkPerimeter", "NP06_TempRulesCheck.cs")
        };

        foreach (var file in files)
        {
            var source = File.ReadAllText(file);

            Assert.Contains("CommandRunner.RunForOutput", source);
            Assert.DoesNotContain("new System.Diagnostics.ProcessStartInfo(\"netsh\"", source);
            Assert.DoesNotContain("StandardOutput.ReadToEnd()", source);
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

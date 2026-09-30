namespace NetworkSecurityAuditor.Tests;

using System.Diagnostics;

/// <summary>
/// Runs a started-by-the-test console process to exit. Both pipes are drained while it runs, since a full pipe
/// blocks the child, and a child that outlives the timeout is killed with its tree instead of being left running.
/// </summary>
internal static class TestProcess
{
    /// <summary>Long enough for Windows PowerShell to start on a machine that is busy with parallel builds.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(2);

    /// <param name="process">A process whose start info redirects standard output and standard error.</param>
    /// <param name="what">Names the tool in failure messages, for example "The release verifier".</param>
    public static (int ExitCode, string Output) RunToExit(Process process, string what, TimeSpan? timeout = null)
    {
        Assert.True(process.Start(), $"Failed to launch {what}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        var limit = timeout ?? DefaultTimeout;
        if (!process.WaitForExit(limit))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // It exited between the wait and the kill.
            }
            Assert.Fail($"{what} did not finish within {limit.TotalSeconds:0} seconds.");
        }

        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}

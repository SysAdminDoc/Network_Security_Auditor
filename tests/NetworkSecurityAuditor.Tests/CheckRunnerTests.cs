using System.Diagnostics;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CheckRunnerTests
{
    [Fact]
    public async Task Blocking_Check_Is_Abandoned_When_Timeout_Expires()
    {
        using var releaseCheck = new ManualResetEventSlim(false);
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new BlockingSecurityCheck(releaseCheck)
        });
        var options = new AuditOptions
        {
            ScanProfile = ScanProfileType.Quick,
            CheckTimeoutSeconds = 1
        };

        var sw = Stopwatch.StartNew();
        var results = await runner.RunAsync(new EnvironmentInfo(), options, null, CancellationToken.None);
        sw.Stop();
        releaseCheck.Set();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Runner waited {sw.Elapsed} for a blocked check.");
        Assert.True(results["EP01"].TimedOut);
        Assert.Equal(CheckStatus.NA, results["EP01"].Status);
        Assert.Contains("timed out", results["EP01"].Findings);
    }

    [Fact]
    public async Task RunAsync_Reports_Check_Start_Before_Result()
    {
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new PassingSecurityCheck()
        });
        var starts = new List<string>();
        var completions = new List<string>();

        await runner.RunAsync(
            new EnvironmentInfo(),
            new AuditOptions { ScanProfile = ScanProfileType.Quick },
            new RecordingProgress<(string checkId, CheckResult result)>(update => completions.Add(update.checkId)),
            CancellationToken.None,
            new RecordingProgress<(string checkId, int index, int total)>(update => starts.Add(update.checkId)));

        Assert.Contains("EP01", starts);
        Assert.Contains("EP01", completions);
        Assert.True(starts.IndexOf("EP01") <= completions.IndexOf("EP01"));
    }

    private sealed class BlockingSecurityCheck(ManualResetEventSlim releaseCheck) : ISecurityCheck
    {
        public string Id => "EP01";

        public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        {
            releaseCheck.Wait();
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Pass,
                Findings = "Released",
                Evidence = "Released by test"
            });
        }
    }

    private sealed class PassingSecurityCheck : ISecurityCheck
    {
        public string Id => "EP01";

        public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Pass,
                Findings = "Passed",
                Evidence = "Immediate"
            });
        }
    }

    private sealed class RecordingProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }
}

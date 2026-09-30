namespace NetworkSecurityAuditor.Tests;

using System.Diagnostics;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

public sealed class HeadlessRunCancellationTests
{
    [Fact]
    public void First_Ctrl_C_Cancels_And_Keeps_The_Process_Alive()
    {
        using var cancellation = new HeadlessRunCancellation(deadline: null);

        Assert.True(cancellation.HandleCancelKeyPress());
        Assert.True(cancellation.Token.IsCancellationRequested);
        Assert.Equal(HeadlessStopReason.CancelKey, cancellation.Reason);
        Assert.Equal("the run was cancelled with Ctrl+C", cancellation.DescribeStop());
    }

    [Fact]
    public void Second_Ctrl_C_Is_Left_To_Windows()
    {
        using var cancellation = new HeadlessRunCancellation(deadline: null);

        cancellation.HandleCancelKeyPress();

        Assert.False(cancellation.HandleCancelKeyPress());
        Assert.False(cancellation.HandleCancelKeyPress());
        Assert.Equal(HeadlessStopReason.CancelKey, cancellation.Reason);
    }

    [Fact]
    public void Deadline_Cancels_And_Names_Itself()
    {
        using var cancellation = new HeadlessRunCancellation(TimeSpan.FromMilliseconds(100));

        Assert.True(cancellation.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(5)));
        Assert.Equal(HeadlessStopReason.Deadline, cancellation.Reason);
        Assert.Equal("the run reached its 0.1-second deadline", cancellation.DescribeStop());

        // A Ctrl+C after the deadline doesn't rewrite why the run stopped.
        Assert.True(cancellation.HandleCancelKeyPress());
        Assert.Equal(HeadlessStopReason.Deadline, cancellation.Reason);
    }

    [Fact]
    public void Nothing_Stops_A_Run_Without_A_Deadline()
    {
        using var cancellation = new HeadlessRunCancellation(deadline: null);

        Assert.False(cancellation.Token.WaitHandle.WaitOne(TimeSpan.FromMilliseconds(200)));
        Assert.Equal(HeadlessStopReason.None, cancellation.Reason);
    }

    [Theory]
    [InlineData(30, "30-minute")]
    [InlineData(1, "1-minute")]
    public void Deadline_Minutes_Are_Named_In_Minutes(int minutes, string expected)
    {
        Assert.Equal(expected, HeadlessRunCancellation.FormatDeadline(TimeSpan.FromMinutes(minutes)));
    }

    [Fact]
    public async Task Deadline_Ends_A_Blocked_Run_With_Partial_Results_And_Exit_Code_69()
    {
        var env = new EnvironmentInfo();
        var options = new AuditOptions { Silent = true, ScanProfile = ScanProfileType.Quick, CheckTimeoutSeconds = 60 };
        var ids = CheckRunner.ResolveApplicableCheckIds(env, options);
        using var release = new ManualResetEventSlim(false);
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            [ids[0]] = new StuckCheck(ids[0], release)
        });
        using var cancellation = new HeadlessRunCancellation(TimeSpan.FromMilliseconds(300));

        var sw = Stopwatch.StartNew();
        var outcome = await runner.RunWithPartialResultsAsync(env, options, cancellation.Token, cancellation.DescribeStop);
        sw.Stop();
        release.Set();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"The deadline took {sw.Elapsed} to end the run.");
        Assert.False(outcome.IsComplete);
        Assert.Equal(ids, outcome.UnfinishedIds);
        Assert.All(outcome.Results.Values, result =>
        {
            Assert.Equal(CheckStatus.Error, result.Status);
            Assert.StartsWith("Incomplete @ ", result.Evidence);
            Assert.Contains("did not finish because the run reached its 0.3-second deadline", result.Findings);
        });

        var exitCode = App.ResolveSilentExitCode(
            outcome.IsComplete, hasScorableChecks: false, score: 0, ransomwareScore: 0,
            frameworkBelowThreshold: () => true, failCount: 0);
        Assert.Equal(ExitCode.RunIncomplete, exitCode);
        Assert.Equal(69, (int)exitCode);
    }

    private sealed class StuckCheck(string id, ManualResetEventSlim release) : ISecurityCheck
    {
        public string Id => id;

        public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        {
            release.Wait(TimeSpan.FromSeconds(30));
            return Task.FromResult(new CheckResult { Status = CheckStatus.Pass, Findings = "late", Evidence = "late" });
        }
    }
}

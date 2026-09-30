using System.Diagnostics;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
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
        Assert.Equal(CheckStatus.Error, results["EP01"].Status);
        Assert.Contains("timed out", results["EP01"].Findings);
        Assert.Matches(@"^Timeout @ \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$", results["EP01"].Evidence);
    }

    [Fact]
    public async Task Blocked_Check_Is_Cancelled_Within_The_Timeout()
    {
        var check = new TokenWaitingCheck("EP01");
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck> { ["EP01"] = check });
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick, CheckTimeoutSeconds = 1 };

        var sw = Stopwatch.StartNew();
        var results = await runner.RunAsync(new EnvironmentInfo(), options, null, CancellationToken.None);
        sw.Stop();

        // The check's own token fires at the timeout, so a check that honours it stops rather than lingering.
        Assert.True(check.Cancelled.Wait(TimeSpan.FromSeconds(3)), "The blocked check's token was never cancelled.");
        Assert.True(check.CancelledAfter < TimeSpan.FromSeconds(3), $"Token fired after {check.CancelledAfter}.");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Runner waited {sw.Elapsed} for a blocked check.");
        Assert.True(results["EP01"].TimedOut);
        Assert.Equal(CheckStatus.Error, results["EP01"].Status);
        Assert.StartsWith("Timeout @ ", results["EP01"].Evidence);
    }

    [Fact]
    public async Task Run_Cancellation_Does_Not_Wait_For_A_Check_That_Ignores_Its_Token()
    {
        using var releaseCheck = new ManualResetEventSlim(false);
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new BlockingSecurityCheck(releaseCheck)
        });
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick, CheckTimeoutSeconds = 60 };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            runner.RunAsync(new EnvironmentInfo(), options, null, cts.Token));
        sw.Stop();
        releaseCheck.Set();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Runner waited {sw.Elapsed} after cancellation.");
    }

    [Fact]
    public async Task Abandoned_Check_Cannot_Write_Into_Results_After_Its_Timeout()
    {
        var env = new EnvironmentInfo();
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick, CheckTimeoutSeconds = 1 };
        var ids = CheckRunner.ResolveApplicableCheckIds(env, options);
        var blocked = new ReleasableCheck(ids[0]);
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck> { [ids[0]] = blocked });
        var reports = new List<(string checkId, CheckResult result)>();

        var results = await runner.RunAsync(env, options, null, CancellationToken.None, completedCallback: reports.Add);
        blocked.Release();
        Assert.True(blocked.Returned.Wait(TimeSpan.FromSeconds(5)), "The abandoned check never returned.");
        await Task.Delay(100);

        Assert.True(results[ids[0]].TimedOut);
        Assert.Single(reports, r => r.checkId == ids[0]);
        Assert.Equal(ids.Length, reports.Count);
        Assert.DoesNotContain(reports, r => r.result.Findings == ReleasableCheck.LateFindings);
    }

    [Fact]
    public async Task RunWithPartialResults_Flags_Every_Unfinished_Check_When_Cancelled()
    {
        var env = new EnvironmentInfo();
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick, CheckTimeoutSeconds = 60 };
        var ids = CheckRunner.ResolveApplicableCheckIds(env, options);
        Assert.True(ids.Length >= 3);
        var blocked = new ReleasableCheck(ids[1]);
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            [ids[0]] = new PassingSecurityCheck(ids[0]),
            [ids[1]] = blocked
        });
        var reports = new List<string>();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        var sw = Stopwatch.StartNew();
        var outcome = await runner.RunWithPartialResultsAsync(
            env, options, cts.Token, () => "the test stopped it", update => reports.Add(update.checkId));
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Partial run took {sw.Elapsed}.");
        Assert.False(outcome.IsComplete);
        Assert.Equal(ids.Length, outcome.Results.Count);
        Assert.Equal(CheckStatus.Pass, outcome.Results[ids[0]].Status);
        Assert.Equal(new[] { ids[0] }, reports);
        Assert.Equal(ids.Skip(1), outcome.UnfinishedIds);
        foreach (var id in ids.Skip(1))
        {
            var result = outcome.Results[id];
            Assert.Equal(CheckStatus.Error, result.Status);
            Assert.True(CheckResult.IsIncompleteEvidence(result.Evidence));
            Assert.Contains($"Check {id} did not finish because the test stopped it.", result.Findings);
            Assert.Contains("partial result", result.Findings);
        }

        // The check that was running is abandoned: when it returns later, nothing reaches the outcome.
        blocked.Release();
        Assert.True(blocked.Returned.Wait(TimeSpan.FromSeconds(5)), "The abandoned check never returned.");
        await Task.Delay(100);
        Assert.True(CheckResult.IsIncompleteEvidence(outcome.Results[ids[1]].Evidence));
        Assert.Equal(new[] { ids[0] }, reports);
    }

    [Fact]
    public async Task RunWithPartialResults_Returns_Complete_Outcome_When_Not_Cancelled()
    {
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new PassingSecurityCheck()
        });
        var env = new EnvironmentInfo();
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick };

        var outcome = await runner.RunWithPartialResultsAsync(env, options, CancellationToken.None, () => "unused");

        Assert.True(outcome.IsComplete);
        Assert.Empty(outcome.UnfinishedIds);
        Assert.Equal(CheckRunner.ResolveApplicableCheckIds(env, options).Length, outcome.Results.Count);
        Assert.DoesNotContain(outcome.Results.Values, r => CheckResult.IsIncompleteEvidence(r.Evidence));
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
            new EnvironmentInfo { IsDomainJoined = true },
            new AuditOptions { ScanProfile = ScanProfileType.Quick },
            new RecordingProgress<(string checkId, CheckResult result)>(update => completions.Add(update.checkId)),
            CancellationToken.None,
            new RecordingProgress<(string checkId, int index, int total)>(update => starts.Add(update.checkId)));

        Assert.Contains("EP01", starts);
        Assert.Contains("EP01", completions);
        Assert.True(starts.IndexOf("EP01") <= completions.IndexOf("EP01"));
    }

    [Fact]
    public async Task RunAsync_Invokes_Completion_Callback_Inline()
    {
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new PassingSecurityCheck()
        });
        var completions = new List<string>();

        await runner.RunAsync(
            new EnvironmentInfo { IsDomainJoined = true },
            new AuditOptions { ScanProfile = ScanProfileType.Quick },
            progress: null,
            ct: CancellationToken.None,
            completedCallback: update => completions.Add(update.checkId));

        Assert.Contains("EP01", completions);
        Assert.Equal(ScanProfiles.Resolve(ScanProfileType.Quick).Length, completions.Count);
    }

    [Fact]
    public void ResolveApplicableCheckIds_Filters_Ad_Checks_When_Not_DomainJoined()
    {
        var applicable = CheckRunner.ResolveApplicableCheckIds(
            new EnvironmentInfo { IsDomainJoined = false },
            new AuditOptions { ScanProfile = ScanProfileType.ADOnly });

        Assert.Empty(applicable);
    }

    [Theory]
    [InlineData("IA03")]
    [InlineData("IA09")]
    public void Registry_Only_Identity_Checks_Run_On_A_Workgroup_Host(string id)
    {
        var applicable = CheckRunner.ResolveApplicableCheckIds(
            new EnvironmentInfo { IsDomainJoined = false },
            new AuditOptions { ScanProfile = ScanProfileType.Full });

        Assert.Contains(id, applicable);
    }

    [Fact]
    public async Task RunAsync_Reports_Applicable_Total_After_Ad_Filtering()
    {
        var runner = new CheckRunner(new Dictionary<string, ISecurityCheck>
        {
            ["EP01"] = new PassingSecurityCheck()
        });
        var totals = new List<int>();
        var options = new AuditOptions { ScanProfile = ScanProfileType.Quick };
        var env = new EnvironmentInfo { IsDomainJoined = false };
        var expectedTotal = CheckRunner.ResolveApplicableCheckIds(env, options).Length;

        await runner.RunAsync(
            env,
            options,
            progress: null,
            ct: CancellationToken.None,
            startedProgress: new RecordingProgress<(string checkId, int index, int total)>(update => totals.Add(update.total)));

        Assert.NotEmpty(totals);
        Assert.All(totals, total => Assert.Equal(expectedTotal, total));
        Assert.True(expectedTotal < ScanProfiles.Resolve(ScanProfileType.Quick).Length);
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

    private sealed class PassingSecurityCheck(string id = "EP01") : ISecurityCheck
    {
        public string Id => id;

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

    /// <summary>Blocks until its token is cancelled, then throws like a well-behaved check.</summary>
    private sealed class TokenWaitingCheck(string id) : ISecurityCheck
    {
        private readonly Stopwatch _clock = new();

        public string Id => id;

        public ManualResetEventSlim Cancelled { get; } = new(false);

        public TimeSpan CancelledAfter { get; private set; }

        public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        {
            _clock.Start();
            ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(30));
            CancelledAfter = _clock.Elapsed;
            if (ct.IsCancellationRequested)
                Cancelled.Set();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new CheckResult { Status = CheckStatus.Pass, Findings = "never", Evidence = "never" });
        }
    }

    /// <summary>Ignores its token and blocks until the test releases it, then returns a result nobody should see.</summary>
    private sealed class ReleasableCheck(string id) : ISecurityCheck
    {
        public const string LateFindings = "Returned after the runner gave up";

        private readonly ManualResetEventSlim _release = new(false);

        public string Id => id;

        public ManualResetEventSlim Returned { get; } = new(false);

        public void Release() => _release.Set();

        public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        {
            _release.Wait(TimeSpan.FromSeconds(30));
            Returned.Set();
            return Task.FromResult(new CheckResult { Status = CheckStatus.Pass, Findings = LateFindings, Evidence = "late" });
        }
    }

    private sealed class RecordingProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }
}

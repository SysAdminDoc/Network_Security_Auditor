namespace NetworkSecurityAuditor.Checks;

using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;

public sealed class CheckRunner
{
    private readonly Dictionary<string, ISecurityCheck> _checks;

    public CheckRunner(Dictionary<string, ISecurityCheck> checks)
    {
        _checks = checks;
    }

    /// <summary>
    /// Runs the applicable checks for the given environment and options.
    /// Reports progress per-check as each completes.
    /// </summary>
    public async Task<Dictionary<string, CheckResult>> RunAsync(
        EnvironmentInfo env,
        AuditOptions options,
        IProgress<(string checkId, CheckResult result)>? progress,
        CancellationToken ct,
        IProgress<(string checkId, int index, int total)>? startedProgress = null,
        Action<(string checkId, CheckResult result)>? completedCallback = null)
    {
        var results = new Dictionary<string, CheckResult>();
        var applicableIds = ResolveApplicableCheckIds(env, options);
        var total = applicableIds.Length;
        var index = 0;

        foreach (var checkId in applicableIds)
        {
            ct.ThrowIfCancellationRequested();
            index++;
            startedProgress?.Report((checkId, index, total));

            if (!_checks.TryGetValue(checkId, out var check))
            {
                var stub = CheckResult.NotImplemented(checkId);
                results[checkId] = stub;
                completedCallback?.Invoke((checkId, stub));
                progress?.Report((checkId, stub));
                continue;
            }

            var result = await RunSingleCheckAsync(check, env, options, ct);
            results[checkId] = result;
            completedCallback?.Invoke((checkId, result));
            progress?.Report((checkId, result));
        }

        return results;
    }

    /// <summary>
    /// Runs like <see cref="RunAsync"/>, but when <paramref name="ct"/> is cancelled it returns instead of
    /// throwing: every check that finished keeps its result, and every applicable check that didn't gets
    /// <see cref="CheckResult.Incomplete"/> with the reason <paramref name="incompleteReason"/> gives. The check
    /// that was running is abandoned, and nothing it does later can reach the returned results.
    /// </summary>
    public async Task<CheckRunOutcome> RunWithPartialResultsAsync(
        EnvironmentInfo env,
        AuditOptions options,
        CancellationToken ct,
        Func<string> incompleteReason,
        Action<(string checkId, CheckResult result)>? completedCallback = null)
    {
        var finished = new Dictionary<string, CheckResult>();
        var closed = false;

        // The runner reports inline, so once the run is over nothing can add to these results.
        void Record((string checkId, CheckResult result) update)
        {
            if (closed)
                return;
            finished[update.checkId] = update.result;
            completedCallback?.Invoke(update);
        }

        try
        {
            var results = await RunAsync(env, options, progress: null, ct, completedCallback: Record);
            closed = true;
            return new CheckRunOutcome(results, []);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            closed = true;
            var partial = new Dictionary<string, CheckResult>(finished);
            var unfinished = new List<string>();
            var reason = incompleteReason();
            foreach (var checkId in ResolveApplicableCheckIds(env, options))
            {
                if (partial.ContainsKey(checkId))
                    continue;
                unfinished.Add(checkId);
                partial[checkId] = CheckResult.Incomplete(checkId, reason);
            }

            return new CheckRunOutcome(partial, unfinished);
        }
    }

    private async Task<CheckResult> RunSingleCheckAsync(
        ISecurityCheck check,
        EnvironmentInfo env,
        AuditOptions options,
        CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var timeout = TimeSpan.FromSeconds(options.CheckTimeoutSeconds);
            using var timeoutCts = new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            var checkToken = linkedCts.Token;

            // Most checks are synchronous and can't be interrupted if they ignore their token. Each one gets its
            // own thread, so a check the runner gives up on keeps only that thread busy and never starves the
            // pool that the timeout and the rest of the run depend on.
            var checkTask = Task.Factory.StartNew(
                () => check.ExecuteAsync(env, options, checkToken),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default).Unwrap();
            var timeoutTask = Task.Delay(timeout, ct);
            var completedTask = await Task.WhenAny(checkTask, timeoutTask);

            if (completedTask != checkTask)
            {
                timeoutCts.Cancel();
                ObserveLateFault(checkTask);
                ct.ThrowIfCancellationRequested();
                sw.Stop();
                return TimeoutResult(check.Id, options.CheckTimeoutSeconds, sw.Elapsed);
            }

            var result = await checkTask;
            sw.Stop();

            return result with { Duration = sw.Elapsed };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            sw.Stop();
            return new CheckResult
            {
                Status = CheckStatus.Error,
                Findings = $"Check {check.Id} timed out after {options.CheckTimeoutSeconds}s.",
                Evidence = $"Timeout @ {CheckResult.EvidenceTimestampUtc()}",
                Duration = sw.Elapsed,
                TimedOut = true
            };
        }
        catch (OperationCanceledException)
        {
            // User-initiated cancellation — rethrow
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            var error = CheckResult.FromError(check.Id, ex);
            return error with { Duration = sw.Elapsed };
        }
    }

    private static CheckResult TimeoutResult(string checkId, int timeoutSeconds, TimeSpan duration) => new()
    {
        Status = CheckStatus.Error,
        Findings = $"Check {checkId} timed out after {timeoutSeconds}s.",
        Evidence = $"Timeout @ {CheckResult.EvidenceTimestampUtc()}",
        Duration = duration,
        TimedOut = true
    };

    private static void ObserveLateFault(Task<CheckResult> abandonedTask)
    {
        _ = abandonedTask.ContinueWith(
            task => _ = task.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>
    /// Determines which check IDs apply for the current profile and environment.
    /// </summary>
    internal static string[] ResolveApplicableCheckIds(EnvironmentInfo env, AuditOptions options)
    {
        var profileCheckIds = ScanProfiles.Resolve(options.ScanProfile);
        var applicable = new List<string>(profileCheckIds.Length);

        foreach (var id in profileCheckIds)
        {
            // Filter AD-only checks when not domain-joined
            if (!env.IsDomainJoined && IsAdCheck(id))
                continue;

            applicable.Add(id);
        }

        return [.. applicable];
    }

    private static bool IsAdCheck(string checkId)
    {
        return CheckCatalog.All.TryGetValue(checkId, out var meta) && meta.Type == CheckType.AD;
    }
}

/// <summary>A run's results, and the applicable checks it didn't finish (empty when the run completed).</summary>
public sealed record CheckRunOutcome(Dictionary<string, CheckResult> Results, IReadOnlyList<string> UnfinishedIds)
{
    public bool IsComplete => UnfinishedIds.Count == 0;
}

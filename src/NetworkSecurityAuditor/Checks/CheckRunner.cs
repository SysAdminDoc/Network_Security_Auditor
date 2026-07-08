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
        var applicableIds = GetApplicableCheckIds(env, options);
        var total = applicableIds.Count;
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

            var checkTask = Task.Run(
                async () => await check.ExecuteAsync(env, options, linkedCts.Token),
                CancellationToken.None);
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
                Status = CheckStatus.NA,
                Findings = $"Check {check.Id} timed out after {options.CheckTimeoutSeconds}s.",
                Evidence = $"Timeout @ {DateTime.Now:yyyy-MM-dd HH:mm}",
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
        Status = CheckStatus.NA,
        Findings = $"Check {checkId} timed out after {timeoutSeconds}s.",
        Evidence = $"Timeout @ {DateTime.Now:yyyy-MM-dd HH:mm}",
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
    private List<string> GetApplicableCheckIds(EnvironmentInfo env, AuditOptions options)
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

        return applicable;
    }

    private static bool IsAdCheck(string checkId)
    {
        return CheckCatalog.All.TryGetValue(checkId, out var meta) && meta.Type == CheckType.AD;
    }
}

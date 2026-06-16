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
        CancellationToken ct)
    {
        var results = new Dictionary<string, CheckResult>();
        var applicableIds = GetApplicableCheckIds(env, options);

        foreach (var checkId in applicableIds)
        {
            ct.ThrowIfCancellationRequested();

            if (!_checks.TryGetValue(checkId, out var check))
            {
                var stub = CheckResult.NotImplemented(checkId);
                results[checkId] = stub;
                progress?.Report((checkId, stub));
                continue;
            }

            var result = await RunSingleCheckAsync(check, env, options, ct);
            results[checkId] = result;
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
            using var timeoutCts = new CancellationTokenSource(timeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var result = await check.ExecuteAsync(env, options, linkedCts.Token);
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

    /// <summary>
    /// AD checks by convention use category prefixes that require domain membership.
    /// </summary>
    private static bool IsAdCheck(string checkId)
    {
        // AD-prefixed checks, and specific checks that require AD
        return checkId.StartsWith("AD", StringComparison.OrdinalIgnoreCase);
    }
}

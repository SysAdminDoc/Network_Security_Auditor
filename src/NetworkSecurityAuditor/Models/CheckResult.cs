namespace NetworkSecurityAuditor.Models;

using System.Globalization;

public sealed record CheckResult
{
    public required CheckStatus Status { get; init; }
    public required string Findings { get; init; }
    public required string Evidence { get; init; }
    public TimeSpan Duration { get; init; }
    public bool TimedOut { get; init; }
    public string? Error { get; init; }

    public static CheckResult NotImplemented(string checkId) => new()
    {
        Status = CheckStatus.NA,
        Findings = $"Check {checkId} is not yet implemented in this version.",
        Evidence = $"Not implemented @ {EvidenceTimestampUtc()}"
    };

    public static CheckResult FromError(string checkId, Exception ex) => new()
    {
        Status = CheckStatus.Error,
        Findings = $"Check {checkId} failed: {ex.Message}",
        Evidence = $"Error @ {EvidenceTimestampUtc()}",
        Error = ex.Message
    };

    /// <summary>
    /// A check that never finished because the whole run was cancelled or hit its deadline. It's an Error so it
    /// stays out of every score, and the "Incomplete @ ..." evidence marks the export as partial.
    /// </summary>
    public static CheckResult Incomplete(string checkId, string reason) => new()
    {
        Status = CheckStatus.Error,
        Findings = $"Check {checkId} did not finish because {reason}. This is a partial result: the check was not assessed.",
        Evidence = $"Incomplete @ {EvidenceTimestampUtc()}",
        Error = $"Incomplete: {reason}"
    };

    /// <summary>The headless run stamps a check it never finished "Incomplete @ ...".</summary>
    public static bool IsIncompleteEvidence(string? evidence) =>
        evidence is not null && evidence.StartsWith("Incomplete @ ", StringComparison.Ordinal);

    /// <summary>The runner stamps a timed-out check's evidence "Timeout @ ..."; saved states keep only the evidence.</summary>
    public static bool IsTimeoutEvidence(string? evidence) =>
        evidence is not null && evidence.StartsWith("Timeout @ ", StringComparison.Ordinal);

    /// <summary>The runner stamps a check that threw "Error @ ...".</summary>
    public static bool IsErrorEvidence(string? evidence) =>
        evidence is not null && evidence.StartsWith("Error @ ", StringComparison.Ordinal);

    internal static string EvidenceTimestampUtc() =>
        DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}

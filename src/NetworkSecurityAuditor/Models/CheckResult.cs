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

    /// <summary>The runner stamps a timed-out check's evidence "Timeout @ ..."; saved states keep only the evidence.</summary>
    public static bool IsTimeoutEvidence(string? evidence) =>
        evidence is not null && evidence.StartsWith("Timeout @ ", StringComparison.Ordinal);

    /// <summary>The runner stamps a check that threw "Error @ ...".</summary>
    public static bool IsErrorEvidence(string? evidence) =>
        evidence is not null && evidence.StartsWith("Error @ ", StringComparison.Ordinal);

    internal static string EvidenceTimestampUtc() =>
        DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}

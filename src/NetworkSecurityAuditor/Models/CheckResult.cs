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
        Status = CheckStatus.NA,
        Findings = $"Check {checkId} failed: {ex.Message}",
        Evidence = $"Error @ {EvidenceTimestampUtc()}",
        Error = ex.Message
    };

    internal static string EvidenceTimestampUtc() =>
        DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}

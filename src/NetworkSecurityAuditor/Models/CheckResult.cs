namespace NetworkSecurityAuditor.Models;

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
        Evidence = $"Not implemented @ {DateTime.Now:yyyy-MM-dd HH:mm}"
    };

    public static CheckResult FromError(string checkId, Exception ex) => new()
    {
        Status = CheckStatus.NA,
        Findings = $"Check {checkId} failed: {ex.Message}",
        Evidence = $"Error @ {DateTime.Now:yyyy-MM-dd HH:mm}",
        Error = ex.Message
    };
}

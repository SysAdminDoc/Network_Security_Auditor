namespace NetworkSecurityAuditor.Models;

public sealed class AttackMapping
{
    public required string[] Tactics { get; init; }
    public required string[] Techniques { get; init; }
    public required string Description { get; init; }
}

public sealed class DefendMapping
{
    public required string[] Stages { get; init; }
    public required string[] Techniques { get; init; }
    public required string[] Labels { get; init; }
    public required string Description { get; init; }
}

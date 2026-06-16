namespace NetworkSecurityAuditor.Checks;

using NetworkSecurityAuditor.Models;

public interface ISecurityCheck
{
    string Id { get; }
    Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct);
}

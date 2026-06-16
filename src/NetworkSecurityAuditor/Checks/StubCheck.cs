namespace NetworkSecurityAuditor.Checks;

using NetworkSecurityAuditor.Models;

public sealed class StubCheck(string id) : ISecurityCheck
{
    public string Id => id;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
        => Task.FromResult(CheckResult.NotImplemented(id));
}

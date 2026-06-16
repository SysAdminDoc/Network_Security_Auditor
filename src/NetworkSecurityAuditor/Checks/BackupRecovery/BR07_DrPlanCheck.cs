namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// BR07 - DR Plan: Checklist check. Report that disaster recovery plan needs manual verification.
/// </summary>
public sealed class BR07_DrPlanCheck : ISecurityCheck
{
    public string Id => "BR07";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            evidence.AppendLine("[Disaster Recovery Plan Review]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");
            evidence.AppendLine("  Note: DR plan verification requires interview with IT management.");

            sb.AppendLine("CHECKLIST - Disaster Recovery Plan:");
            sb.AppendLine("  [ ] Written DR plan exists and is maintained");
            sb.AppendLine("  [ ] DR plan covers all critical business systems");
            sb.AppendLine("  [ ] Recovery procedures are documented step-by-step");
            sb.AppendLine("  [ ] DR plan includes communication procedures");
            sb.AppendLine("  [ ] Contact lists and escalation paths are current");
            sb.AppendLine("  [ ] DR plan is tested at least annually (tabletop or full)");
            sb.AppendLine("  [ ] Last DR test date and results are documented");
            sb.AppendLine("  [ ] DR plan addresses ransomware/cyber incident recovery");
            sb.AppendLine("  [ ] DR site/alternate processing location is identified");
            sb.AppendLine("  [ ] DR plan is stored offsite/accessible during outage");
            sb.AppendLine("  [ ] Key personnel are trained on DR procedures");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview IT management to review " +
                "disaster recovery plan, test results, and update frequency.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }
}

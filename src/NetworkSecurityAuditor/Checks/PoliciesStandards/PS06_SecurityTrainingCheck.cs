namespace NetworkSecurityAuditor.Checks.PoliciesStandards;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// PS06 - Security Training: Checklist check. Report that training needs manual verification.
/// </summary>
public sealed class PS06_SecurityTrainingCheck : ISecurityCheck
{
    public string Id => "PS06";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            evidence.AppendLine("[Security Training Review]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");
            evidence.AppendLine("  Note: Security training verification requires interview with HR/IT.");

            sb.AppendLine("CHECKLIST - Security Training Program:");
            sb.AppendLine("  [ ] IT/security staff receive role-specific technical training");
            sb.AppendLine("  [ ] IT staff certifications are current (CompTIA, CISSP, CEH, etc.)");
            sb.AppendLine("  [ ] Training covers: incident response procedures");
            sb.AppendLine("  [ ] Training covers: secure configuration and hardening");
            sb.AppendLine("  [ ] Training covers: vulnerability management");
            sb.AppendLine("  [ ] Training covers: cloud security (if applicable)");
            sb.AppendLine("  [ ] Training budget is allocated annually");
            sb.AppendLine("  [ ] Training completion is tracked");
            sb.AppendLine("  [ ] New technology deployments include training component");
            sb.AppendLine("  [ ] Cross-training ensures coverage for key security functions");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview HR/IT management to review " +
                "security training program, completion records, and certification tracking.");

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

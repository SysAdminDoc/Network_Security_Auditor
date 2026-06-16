namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF03 - Security Awareness: Interview-required checklist. Report that security training
/// needs manual verification.
/// </summary>
public sealed class CF03_SecurityAwarenessCheck : ISecurityCheck
{
    public string Id => "CF03";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool trainingIndicator = false;

            evidence.AppendLine("[Security Awareness Training Review]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");

            // Check for training platform software indicators
            CheckTrainingPlatforms(sb, evidence, ref trainingIndicator);

            if (trainingIndicator)
            {
                sb.Insert(0, "Security awareness training platform indicators detected.\n");
            }
            else
            {
                sb.Insert(0, "No security awareness training indicators detected on this host.\n");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Security Awareness Training:");
            sb.AppendLine("  [ ] Formal security awareness training program exists");
            sb.AppendLine("  [ ] All employees complete annual security training");
            sb.AppendLine("  [ ] New hire security training is part of onboarding");
            sb.AppendLine("  [ ] Phishing simulation campaigns are conducted regularly");
            sb.AppendLine("  [ ] Training covers: phishing, social engineering, password hygiene, data handling");
            sb.AppendLine("  [ ] Training completion is tracked and reported to management");
            sb.AppendLine("  [ ] Repeat offenders receive additional training");
            sb.AppendLine("  [ ] Training content is updated at least annually");
            sb.AppendLine("  [ ] Role-specific training for privileged users/IT staff");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview HR/IT to verify security " +
                "awareness training program, completion rates, and phishing simulation results.");

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

    private static void CheckTrainingPlatforms(StringBuilder sb, StringBuilder evidence,
        ref bool trainingIndicator)
    {
        evidence.AppendLine("\n[Training Platform Indicators]");

        var platforms = new Dictionary<string, string>
        {
            { @"HKLM\SOFTWARE\KnowBe4", "KnowBe4" },
            { @"HKLM\SOFTWARE\Proofpoint\Security Awareness Training", "Proofpoint SAT" },
            { @"HKLM\SOFTWARE\Mimecast", "Mimecast Awareness Training" },
            { @"HKLM\SOFTWARE\SANS", "SANS Security Awareness" },
        };

        foreach (var (path, label) in platforms)
        {
            if (Services.RegistryHelper.KeyExists(path))
            {
                trainingIndicator = true;
                evidence.AppendLine($"  FOUND: {label}");
                sb.AppendLine($"Training platform detected: {label}");
            }
        }

        if (!trainingIndicator)
            evidence.AppendLine("  No training platform registry keys found.");
    }
}

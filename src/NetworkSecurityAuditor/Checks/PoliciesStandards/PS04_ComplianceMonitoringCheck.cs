namespace NetworkSecurityAuditor.Checks.PoliciesStandards;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// PS04 - Compliance Monitoring: Checklist check. Report compliance monitoring
/// needs manual verification.
/// </summary>
public sealed class PS04_ComplianceMonitoringCheck : ISecurityCheck
{
    public string Id => "PS04";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int indicators = 0;

            evidence.AppendLine("[Compliance Monitoring Indicators]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");

            // Check for compliance-related tools
            ct.ThrowIfCancellationRequested();

            var complianceTools = new Dictionary<string, string>
            {
                { @"HKLM\SOFTWARE\Qualys", "Qualys" },
                { @"HKLM\SOFTWARE\Tenable\Nessus Agent", "Tenable Nessus" },
                { @"HKLM\SOFTWARE\Rapid7", "Rapid7" },
                { @"HKLM\SOFTWARE\Microsoft\PolicyManager", "Microsoft Policy Manager" },
                { @"HKLM\SOFTWARE\CIS", "CIS Benchmark Tools" },
                { @"HKLM\SOFTWARE\DISA", "DISA STIG Tools" },
            };

            foreach (var (path, label) in complianceTools)
            {
                if (RegistryHelper.KeyExists(path))
                {
                    indicators++;
                    evidence.AppendLine($"  FOUND: {label}");
                    sb.AppendLine($"Compliance tool detected: {label}");
                }
            }

            // Check if Intune manages this device
            if (env.IntuneManaged)
            {
                indicators++;
                evidence.AppendLine("  Intune managed: Yes (compliance policies may be enforced)");
                sb.AppendLine("Device is Intune-managed (compliance policies active).");
            }

            sb.AppendLine($"\nCompliance monitoring indicators: {indicators}");
            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Compliance Monitoring:");
            sb.AppendLine("  [ ] Compliance requirements are identified (HIPAA, PCI-DSS, SOC 2, NIST, etc.)");
            sb.AppendLine("  [ ] Compliance monitoring tools/processes are in place");
            sb.AppendLine("  [ ] Regular compliance assessments are conducted");
            sb.AppendLine("  [ ] Compliance gaps are tracked and remediated");
            sb.AppendLine("  [ ] Compliance reports are generated for management");
            sb.AppendLine("  [ ] Regulatory changes are monitored and policies updated");
            sb.AppendLine("  [ ] Third-party vendor compliance is assessed");
            sb.AppendLine("  [ ] Evidence of compliance is retained per requirements");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview compliance officer/IT " +
                "to verify compliance framework adoption and monitoring processes.");

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

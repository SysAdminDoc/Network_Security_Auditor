using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class JsonlExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public static string Export(
        ObservableCollection<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        ScanProfileType profile)
    {
        var sb = new StringBuilder();
        var timestamp = DateTime.UtcNow.ToString("o");

        foreach (var check in checks)
        {
            if (check.Status == CheckStatus.NotAssessed) continue;

            var compliance = FrameworkMappings.All.GetValueOrDefault(check.Id);
            var findings = check.Findings;
            var evidence = check.Evidence;
            var findingsTruncated = false;
            var evidenceTruncated = false;

            if (findings.Length > 4000)
            {
                findings = findings[..4000];
                findingsTruncated = true;
            }
            if (evidence.Length > 2000)
            {
                evidence = evidence[..2000];
                evidenceTruncated = true;
            }

            var evt = new
            {
                event_type = "security_finding",
                tool = "NetworkSecurityAuditor",
                tool_version = "5.0.0",
                timestamp,
                host = env.ComputerName,
                os = env.OSCaption,
                domain = env.DomainName,
                scan_profile = profile.ToString(),
                overall_score = overallScore,
                overall_grade = grade,
                check_id = check.Id,
                category = check.Category,
                label = check.Label,
                severity = check.Severity.ToString(),
                status = check.Status.ToString(),
                findings,
                findings_truncated = findingsTruncated,
                evidence,
                evidence_truncated = evidenceTruncated,
                nist = compliance?.NIST,
                cmmc = compliance?.CMMC,
                pci = compliance?.PCI,
                soc2 = compliance?.SOC2,
                iso27001 = compliance?.ISO27001,
                stig = compliance?.STIG,
                fedramp = compliance?.FedRAMP
            };

            sb.AppendLine(JsonSerializer.Serialize(evt, Options));
        }

        return sb.ToString();
    }
}

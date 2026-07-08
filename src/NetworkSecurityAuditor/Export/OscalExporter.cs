using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

/// <summary>
/// NIST OSCAL v1.1.3 Assessment Results exporter.
/// Produces observations, findings, and risks per the OSCAL assessment-results model.
/// </summary>
public static class OscalExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade)
    {
        var checkList = checks.ToList();
        var timestamp = DateTime.UtcNow.ToString("o");
        var runId = Guid.NewGuid().ToString();

        var observations = new List<object>();
        var findings = new List<object>();
        var risks = new List<object>();

        foreach (var check in checkList)
        {
            if (check.Status == CheckStatus.NotAssessed) continue;
            var mapping = FrameworkMappings.All.GetValueOrDefault(check.Id);

            var obsUuid = Guid.NewGuid().ToString();
            observations.Add(new
            {
                uuid = obsUuid,
                title = $"[{check.Id}] {check.Label}",
                description = !string.IsNullOrEmpty(check.Findings) ? check.Findings : "No findings recorded.",
                methods = new[] { check.EvidenceMode switch
                {
                    EvidenceMode.Automated => "TEST",
                    EvidenceMode.Heuristic => "EXAMINE",
                    EvidenceMode.InterviewRequired => "INTERVIEW",
                    _ => "EXAMINE"
                }},
                types = new[] { "finding" },
                collected = timestamp,
                subjects = new[]
                {
                    new { subjectUuid = runId, type = "component", title = env.ComputerName }
                },
                relevantEvidence = !string.IsNullOrEmpty(check.Evidence) ? new[]
                {
                    new { description = check.Evidence.Length > 2000 ? check.Evidence[..2000] : check.Evidence }
                } : null
            });

            if (check.Status is CheckStatus.Fail or CheckStatus.Partial)
            {
                var props = new List<object>();
                if (mapping?.CIS is not null) props.Add(new { name = "cis", value = mapping.CIS });
                if (mapping?.CMMC is not null) props.Add(new { name = "cmmc", value = mapping.CMMC });
                if (mapping?.HIPAA is not null) props.Add(new { name = "hipaa", value = mapping.HIPAA });
                if (mapping?.PCI is not null) props.Add(new { name = "pci-dss", value = mapping.PCI });
                if (mapping?.SOC2 is not null) props.Add(new { name = "soc2", value = mapping.SOC2 });
                if (mapping?.ISO27001 is not null) props.Add(new { name = "iso27001", value = mapping.ISO27001 });
                if (mapping?.STIG is not null) props.Add(new { name = "stig", value = mapping.STIG });
                if (mapping?.FedRAMP is not null) props.Add(new { name = "fedramp", value = mapping.FedRAMP });
                if (mapping?.E8 is not null) props.Add(new { name = "essential-eight", value = mapping.E8 });
                if (mapping?.CyberEssentials is not null) props.Add(new { name = "cyber-essentials", value = mapping.CyberEssentials });

                findings.Add(new
                {
                    uuid = Guid.NewGuid().ToString(),
                    title = $"[{check.Id}] {check.Label}",
                    description = check.Findings,
                    target = new
                    {
                        type = "objective-id",
                        targetId = mapping?.NIST ?? check.Id,
                        status = new
                        {
                            state = "not-satisfied",
                            reason = check.Status == CheckStatus.Fail ? "fail" : "other"
                        }
                    },
                    relatedObservations = new[]
                    {
                        new { observationUuid = obsUuid }
                    },
                    props = props.Count > 0 ? props : null
                });

                if (check.Status == CheckStatus.Fail && check.Severity >= Severity.High)
                {
                    risks.Add(new
                    {
                        uuid = Guid.NewGuid().ToString(),
                        title = $"Risk: {check.Label}",
                        description = check.Findings,
                        status = "open",
                        props = new[]
                        {
                            new
                            {
                                name = "risk-level",
                                value = check.Severity == Severity.Critical ? "high" : "moderate"
                            }
                        }
                    });
                }
            }
        }

        var oscal = new
        {
            assessmentResults = new
            {
                uuid = Guid.NewGuid().ToString(),
                metadata = new
                {
                    title = $"Security Assessment - {env.ComputerName}",
                    lastModified = timestamp,
                    version = "1.0.0",
                    oscalVersion = "1.1.3",
                    roles = new[]
                    {
                        new { id = "assessor", title = "Security Assessor" }
                    },
                    parties = new[]
                    {
                        new { uuid = Guid.NewGuid().ToString(), type = "tool", name = $"Network Security Auditor v{VersionInfo.Version}" }
                    }
                },
                results = new[]
                {
                    new
                    {
                        uuid = runId,
                        title = $"Assessment of {env.ComputerName}",
                        description = $"Automated security assessment: score {overallScore}/100 ({grade})",
                        start = timestamp,
                        end = timestamp,
                        observations,
                        findings,
                        risks
                    }
                }
            }
        };

        return JsonSerializer.Serialize(oscal, Options);
    }
}

using System.Text;
using System.Text.Json;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

/// <summary>
/// OCSF Compliance Finding (class 2003) exporter.
/// Security Finding (class 2001) was deprecated in OCSF v1.1.0.
/// </summary>
public static class OcsfExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        string scanProfile)
    {
        var sb = new StringBuilder();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        foreach (var check in checks)
        {
            if (check.Status == CheckStatus.NotAssessed) continue;

            var compliance = FrameworkMappings.All.GetValueOrDefault(check.Id);
            var mitre = MitreMappings.All.GetValueOrDefault(check.Id);

            var evt = new
            {
                class_uid = 2003,
                class_name = "Compliance Finding",
                category_uid = 2,
                category_name = "Findings",
                severity_id = check.Severity switch
                {
                    Severity.Critical => 5,
                    Severity.High => 4,
                    Severity.Medium => 3,
                    Severity.Low => 2,
                    _ => 1
                },
                severity = check.Severity.ToString(),
                status_id = check.Status switch
                {
                    CheckStatus.Pass => 1,
                    CheckStatus.Fail => 2,
                    CheckStatus.Partial => 6,
                    CheckStatus.NA => 0,
                    _ => 99
                },
                status = check.Status.ToString(),
                activity_id = 1,
                activity_name = "Create",
                type_uid = 200301,
                type_name = "Compliance Finding: Create",
                time = timestamp,
                message = !string.IsNullOrEmpty(check.Findings) ? check.Findings : check.Label,
                metadata = new
                {
                    version = "1.4.0",
                    product = new
                    {
                        name = "Network Security Auditor",
                        version = VersionInfo.Version,
                        vendor_name = "SysAdminDoc"
                    },
                    profiles = new[] { "security_control" }
                },
                finding_info = new
                {
                    uid = check.Id,
                    title = $"[{check.Id}] {check.Label}",
                    desc = check.Findings,
                    types = new[] { check.Category },
                    created_time = timestamp,
                    src_url = check.RemediationUrl
                },
                compliance = new
                {
                    requirements = BuildRequirements(compliance),
                    status = check.Status == CheckStatus.Pass ? "Pass" : check.Status == CheckStatus.Fail ? "Fail" : "Other",
                    status_detail = check.Evidence
                },
                resource = new
                {
                    name = env.ComputerName,
                    type = env.IsServer ? "Server" : "Workstation",
                    uid = env.ComputerName,
                    labels = new[] { $"os:{env.OSCaption}", $"domain:{env.DomainName}", $"profile:{scanProfile}" }
                },
                attacks = mitre is not null ? mitre.Techniques.Select(tech => new
                {
                    tactics = mitre.Tactics.Select(t => new { uid = t, name = t }).ToArray(),
                    technique = new { uid = tech, name = mitre.Description },
                    version = "19.0"
                }).ToArray() : null,
                evidences = !string.IsNullOrEmpty(check.Evidence) ? new[]
                {
                    new { data = check.Evidence.Length > 2000 ? check.Evidence[..2000] : check.Evidence }
                } : null
            };

            sb.AppendLine(JsonSerializer.Serialize(evt, Options));
        }

        return sb.ToString();
    }

    private static string[]? BuildRequirements(ComplianceMapping? mapping)
    {
        if (mapping is null) return null;
        var reqs = new List<string>();
        if (mapping.CIS is not null) reqs.Add($"CIS {mapping.CIS}");
        if (mapping.NIST is not null) reqs.Add($"NIST 800-171 {mapping.NIST}");
        if (mapping.HIPAA is not null) reqs.Add($"HIPAA {mapping.HIPAA}");
        if (mapping.PCI is not null) reqs.Add($"PCI-DSS {mapping.PCI}");
        if (mapping.STIG is not null) reqs.Add($"DISA STIG {mapping.STIG}");
        return reqs.Count > 0 ? reqs.ToArray() : null;
    }
}

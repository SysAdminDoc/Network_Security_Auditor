using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class DefectDojoExporter
{
    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade)
    {
        var findings = new List<object>();

        foreach (var check in checks)
        {
            if (check.Status is CheckStatus.NotAssessed or CheckStatus.NA)
                continue;

            var meta = CheckCatalog.All.GetValueOrDefault(check.Id);
            var compliance = FrameworkMappings.All.GetValueOrDefault(check.Id);

            var severity = check.Severity switch
            {
                Severity.Critical => "Critical",
                Severity.High => "High",
                Severity.Medium => "Medium",
                Severity.Low => "Low",
                _ => "Info"
            };

            var active = check.Status is CheckStatus.Fail or CheckStatus.Partial;

            var mitre = MitreMappings.All.GetValueOrDefault(check.Id);
            var defend = D3FendMappings.All.GetValueOrDefault(check.Id);

            var references = new List<string>();
            if (meta?.RemediationUrl is not null)
                references.Add(meta.RemediationUrl);
            if (compliance is not null)
            {
                if (compliance.CIS is not null) references.Add($"CIS Controls: {compliance.CIS}");
                if (compliance.NIST is not null) references.Add($"NIST 800-171: {compliance.NIST}");
                if (compliance.CMMC is not null) references.Add($"CMMC: {compliance.CMMC}");
                if (compliance.HIPAA is not null) references.Add($"HIPAA: {compliance.HIPAA}");
                if (compliance.PCI is not null) references.Add($"PCI-DSS: {compliance.PCI}");
                if (compliance.SOC2 is not null) references.Add($"SOC 2: {compliance.SOC2}");
                if (compliance.ISO27001 is not null) references.Add($"ISO 27001: {compliance.ISO27001}");
                if (compliance.STIG is not null) references.Add($"DISA STIG: {compliance.STIG}");
                if (compliance.FedRAMP is not null) references.Add($"FedRAMP: {compliance.FedRAMP}");
                if (compliance.E8 is not null) references.Add($"Essential Eight: {compliance.E8}");
                if (compliance.CyberEssentials is not null) references.Add($"Cyber Essentials: {compliance.CyberEssentials}");
            }
            if (mitre is not null)
                references.Add($"ATT&CK: {string.Join(", ", mitre.Techniques)}");
            if (defend is not null)
                references.Add($"D3FEND: {string.Join(", ", defend.Techniques)}");

            findings.Add(new
            {
                title = $"[{check.Id}] {check.Label}",
                description = check.Findings,
                severity,
                date = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                active,
                verified = true,
                mitigation = meta?.Hint ?? "",
                impact = $"Security score impact: {check.Severity} severity ({(int)check.Severity} points)",
                references = string.Join("\n", references),
                file_path = $"NetworkSecurityAuditor://{check.Category}/{check.Id}",
                unique_id_from_tool = check.Id,
                vuln_id_from_tool = check.Id,
                severity_justification = $"Category: {check.Category} | Weight: {(int)check.Severity}",
                tags = new[] { check.Category, check.Id, $"Grade:{grade}" },
                numerical_severity = check.Severity switch
                {
                    Severity.Critical => "S0",
                    Severity.High => "S1",
                    Severity.Medium => "S2",
                    _ => "S3"
                },
                static_finding = true,
                dynamic_finding = false
            });
        }

        var output = new
        {
            findings,
            scan_type = "Network Security Auditor",
            scan_date = DateTime.UtcNow.ToString("yyyy-MM-dd"),
            engagement_name = $"Security Audit - {env.ComputerName}",
            product_name = $"Network Security Auditor - {env.ComputerName}",
            test_type_name = "Network Security Auditor Scan",
            environment = env.IsDomainJoined ? "Production" : "Development"
        };

        return JsonSerializer.Serialize(output, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }
}

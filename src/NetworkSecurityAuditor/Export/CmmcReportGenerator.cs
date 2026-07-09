using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class CmmcReportGenerator
{
    private static readonly string[] Level1Controls =
    [
        "3.1.1", "3.1.2", "3.1.20",
        "3.3.5",
        "3.5.1", "3.5.2", "3.5.7",
        "3.8.3",
        "3.13.1", "3.13.5",
        "3.14.1", "3.14.2", "3.14.4", "3.14.5", "3.14.6"
    ];

    public static string ExportHtml(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade)
    {
        var checkList = checks.ToList();
        var (sprsScore, sprsConf) = SprsScoreEngine.Calculate(checkList);
        var controlData = BuildControlData(checkList);

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("<title>CMMC Self-Assessment Report</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetCss());
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine("<h1>CMMC Level 2 Self-Assessment Report</h1>");
        sb.AppendLine($"<p class=\"subtitle\">NIST SP 800-171 Rev 2 | {EscapeHtml(env.ComputerName)} | {DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}</p>");
        sb.AppendLine("</div>");

        var sprsColor = sprsScore >= 88 ? "#a6e3a1" : sprsScore >= 50 ? "#f9e2af" : "#f38ba8";
        sb.AppendLine("<div class=\"summary-grid\">");
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{sprsColor};font-size:48px\">{sprsScore}</div><div class=\"score-value\">of 110</div><div class=\"score-label\">SPRS Score ({sprsConf})</div></div>");
        var metCount = controlData.Count(c => c.Status == "Met");
        var notMetCount = controlData.Count(c => c.Status == "Not Met");
        var partialCount = controlData.Count(c => c.Status == "Partially Met");
        var naCount = controlData.Count(c => c.Status == "N/A");
        sb.AppendLine($"<div class=\"score-card\"><div class=\"stat-row\"><span style=\"color:#a6e3a1\">Met: {metCount}</span></div><div class=\"stat-row\"><span style=\"color:#f9e2af\">Partial: {partialCount}</span></div><div class=\"stat-row\"><span style=\"color:#f38ba8\">Not Met: {notMetCount}</span></div><div class=\"stat-row\"><span style=\"color:#7f839b\">N/A: {naCount}</span></div><div class=\"score-label\">Control Status</div></div>");
        var eligible = sprsScore >= 110 ? "Eligible (full)" : sprsScore >= 88 ? "Eligible (conditional with POA&M)" : "Not Eligible";
        var eligColor = sprsScore >= 110 ? "#a6e3a1" : sprsScore >= 88 ? "#f9e2af" : "#f38ba8";
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{eligColor};font-size:24px\">{eligible}</div><div class=\"score-label\">CMMC Level 2 Eligibility</div></div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<h2>Level 1 Practices (FAR 52.204-21)</h2>");
        AppendControlTable(sb, controlData.Where(c => Level1Controls.Contains(c.ControlId)).ToList());

        sb.AppendLine("<h2>All NIST 800-171 Controls</h2>");
        var families = controlData.GroupBy(c => c.Family).OrderBy(g => g.Key);
        foreach (var family in families)
        {
            sb.AppendLine($"<h3>{family.Key}</h3>");
            AppendControlTable(sb, family.OrderBy(c => c.ControlId).ToList());
        }

        sb.AppendLine($"<div class=\"footer\">Network Security Auditor v{VersionInfo.Version} - CMMC Self-Assessment</div>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    public static string ExportJson(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env)
    {
        var checkList = checks.ToList();
        var (sprsScore, sprsConf) = SprsScoreEngine.Calculate(checkList);
        var controlData = BuildControlData(checkList);

        var report = new
        {
            tool = "NetworkSecurityAuditor",
            tool_version = VersionInfo.Version,
            report_type = "cmmc_self_assessment",
            timestamp = DateTime.UtcNow.ToString("o"),
            host = env.ComputerName,
            standard = "NIST SP 800-171 Rev 2",
            sprs_score = sprsScore,
            sprs_confidence = sprsConf,
            controls_met = controlData.Count(c => c.Status == "Met"),
            controls_not_met = controlData.Count(c => c.Status == "Not Met"),
            controls_partial = controlData.Count(c => c.Status == "Partially Met"),
            controls = controlData.Select(c => new
            {
                control_id = c.ControlId,
                family = c.Family,
                status = c.Status,
                weight = c.Weight,
                deduction = c.Deduction,
                check_ids = c.CheckIds,
                evidence_summary = c.EvidenceSummary,
                is_level1 = Level1Controls.Contains(c.ControlId)
            }).ToArray()
        };

        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    private static List<ControlAssessment> BuildControlData(List<CheckItemViewModel> checks)
    {
        var statusLookup = checks.ToDictionary(c => c.Id, c => c, StringComparer.OrdinalIgnoreCase);
        var controlMap = new Dictionary<string, ControlAssessment>(StringComparer.OrdinalIgnoreCase);

        foreach (var (checkId, mapping) in FrameworkMappings.All)
        {
            if (mapping.NIST is null) continue;
            if (!statusLookup.TryGetValue(checkId, out var check)) continue;

            var controls = mapping.NIST.Split(',', StringSplitOptions.TrimEntries);
            foreach (var controlId in controls)
            {
                if (!controlMap.TryGetValue(controlId, out var ca))
                {
                    var family = GetFamily(controlId);
                    var weight = SprsScoreEngine.GetWeight(controlId);
                    ca = new ControlAssessment { ControlId = controlId, Family = family, Weight = weight };
                    controlMap[controlId] = ca;
                }

                ca.CheckIds.Add(checkId);
                if (check.Status is CheckStatus.Fail)
                    ca.FailingChecks.Add(checkId);
                else if (check.Status is CheckStatus.Partial)
                    ca.PartialChecks.Add(checkId);
                else if (check.Status is CheckStatus.Pass)
                    ca.PassingChecks.Add(checkId);

                if (check.Findings.Length > 0)
                {
                    var evidencePriority = EvidencePriority(check.Status);
                    if (evidencePriority > ca.EvidencePriority)
                    {
                        var summary = check.Findings.Length > 200 ? check.Findings[..200] + "..." : check.Findings;
                        ca.EvidenceSummary = $"{checkId}: {summary}";
                        ca.EvidencePriority = evidencePriority;
                    }
                }
            }
        }

        foreach (var ca in controlMap.Values)
        {
            if (ca.FailingChecks.Count > 0)
            {
                ca.Status = "Not Met";
                ca.Deduction = ca.Weight;
            }
            else if (ca.PartialChecks.Count > 0)
            {
                ca.Status = "Partially Met";
                ca.Deduction = 0;
            }
            else if (ca.PassingChecks.Count > 0)
            {
                ca.Status = "Met";
                ca.Deduction = 0;
            }
            else
            {
                ca.Status = "N/A";
                ca.Deduction = 0;
            }
        }

        return controlMap.Values.OrderBy(c => c.ControlId).ToList();
    }

    private static void AppendControlTable(StringBuilder sb, List<ControlAssessment> controls)
    {
        sb.AppendLine("<table>");
        sb.AppendLine("<caption>CMMC control assessment by NIST 800-171 control</caption>");
        sb.AppendLine("<thead><tr><th scope=\"col\">Control</th><th scope=\"col\">Family</th><th scope=\"col\">Status</th><th scope=\"col\">Weight</th><th scope=\"col\">Deduction</th><th scope=\"col\">Checks</th><th scope=\"col\">Evidence</th></tr></thead>");
        sb.AppendLine("<tbody>");
        foreach (var c in controls)
        {
            var statusColor = c.Status switch { "Met" => "#a6e3a1", "Not Met" => "#f38ba8", "Partially Met" => "#f9e2af", _ => "#7f839b" };
            sb.AppendLine($"<tr><td style=\"font-family:monospace;font-weight:600;color:#cba6f7\">{c.ControlId}</td>");
            sb.AppendLine($"<td>{c.Family}</td>");
            sb.AppendLine($"<td style=\"color:{statusColor};font-weight:600\">{c.Status}</td>");
            sb.AppendLine($"<td>{c.Weight}</td><td style=\"color:{(c.Deduction > 0 ? "#f38ba8" : "#a6e3a1")}\">{(c.Deduction > 0 ? $"-{c.Deduction}" : "0")}</td>");
            sb.AppendLine($"<td style=\"font-size:12px\">{string.Join(", ", c.CheckIds)}</td>");
            sb.AppendLine($"<td style=\"font-size:12px;color:#b5bcd6;max-width:300px;word-wrap:break-word\">{EscapeHtml(c.EvidenceSummary)}</td></tr>");
        }
        sb.AppendLine("</tbody>");
        sb.AppendLine("</table>");
    }

    private static int EvidencePriority(CheckStatus status) => status switch
    {
        CheckStatus.Fail => 3,
        CheckStatus.Partial => 2,
        CheckStatus.Pass => 1,
        _ => 0
    };

    private static string GetFamily(string controlId)
    {
        if (!controlId.StartsWith("3.")) return "Unknown";
        var parts = controlId.Split('.');
        if (parts.Length < 2 || !int.TryParse(parts[1], out var num)) return "Unknown";
        return num switch
        {
            1 => "Access Control",
            2 => "Awareness and Training",
            3 => "Audit and Accountability",
            4 => "Configuration Management",
            5 => "Identification and Authentication",
            6 => "Incident Response",
            7 => "Maintenance",
            8 => "Media Protection",
            9 => "Personnel Security",
            10 => "Physical Protection",
            11 => "Risk Assessment",
            12 => "Security Assessment",
            13 => "System and Communications Protection",
            14 => "System and Information Integrity",
            _ => "Unknown"
        };
    }

    private static string EscapeHtml(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string GetCss() => """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 32px; line-height: 1.6; }
        .header { background: #313244; border-radius: 8px; padding: 32px; margin-bottom: 24px; border-left: 4px solid #cba6f7; }
        .header h1 { color: #cba6f7; font-size: 24px; margin-bottom: 8px; }
        .subtitle { color: #b5bcd6; font-size: 14px; }
        h2 { color: #cba6f7; margin: 24px 0 12px; font-size: 20px; }
        h3 { color: #b5bcd6; margin: 16px 0 8px; font-size: 16px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .score-card { background: #313244; border-radius: 8px; padding: 24px; text-align: center; }
        .score-grade { font-weight: 700; }
        .score-value { font-size: 24px; color: #b5bcd6; margin: 4px 0; }
        .score-label { font-size: 13px; color: #7f839b; text-transform: uppercase; letter-spacing: 1px; }
        .stat-row { padding: 4px 0; font-size: 15px; }
        table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }
        caption { text-align: left; color: #b5bcd6; font-size: 12px; padding: 0 0 8px; font-weight: 600; }
        th { background: #45475a; color: #cba6f7; text-align: left; padding: 10px 14px; font-size: 13px; text-transform: uppercase; }
        td { padding: 10px 14px; border-top: 1px solid #45475a; font-size: 14px; }
        tr:hover { background: #3b3d50; }
        .footer { text-align: center; padding: 24px; color: #585b70; font-size: 12px; margin-top: 32px; }
        @media print { body { background: #fff; color: #333; } .header { background: #f5f5f5; } table { background: #fff; } th { background: #eee; } td { border-top-color: #ddd; } }
        """;

    private sealed class ControlAssessment
    {
        public string ControlId { get; set; } = "";
        public string Family { get; set; } = "";
        public int Weight { get; set; }
        public string Status { get; set; } = "N/A";
        public int Deduction { get; set; }
        public List<string> CheckIds { get; set; } = [];
        public List<string> PassingChecks { get; set; } = [];
        public List<string> PartialChecks { get; set; } = [];
        public List<string> FailingChecks { get; set; } = [];
        public string EvidenceSummary { get; set; } = "";
        public int EvidencePriority { get; set; }
    }
}

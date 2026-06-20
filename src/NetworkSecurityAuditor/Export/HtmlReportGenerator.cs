using System.Text;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class HtmlReportGenerator
{
    public static string Generate(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        int ransomwareScore,
        string ransomwareGrade,
        int domainMaturityScore = 0,
        string domainMaturityGrade = "N/A")
    {
        var checkList = checks.ToList();
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("<title>Network Security Audit Report</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetCss());
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine("<h1>Network Security Audit Report</h1>");
        sb.AppendLine($"<p class=\"subtitle\">Generated {DateTime.Now:yyyy-MM-dd HH:mm} | {env.ComputerName} | {env.OSCaption}</p>");
        sb.AppendLine("</div>");

        // Executive Summary
        sb.AppendLine("<div class=\"summary-grid\">");
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{GradeColor(grade)}\">{grade}</div><div class=\"score-value\">{overallScore}/100</div><div class=\"score-label\">Overall Score</div></div>");
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{GradeColor(ransomwareGrade)}\">{ransomwareGrade}</div><div class=\"score-value\">{ransomwareScore}/100</div><div class=\"score-label\">Ransomware Readiness</div></div>");
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{GradeColor(domainMaturityGrade)}\">{domainMaturityGrade}</div><div class=\"score-value\">{domainMaturityScore}/100</div><div class=\"score-label\">Domain Maturity</div></div>");

        var (sprsScore, sprsConf) = Scoring.SprsScoreEngine.Calculate(checkList);
        var sprsColor = sprsScore >= 88 ? "#a6e3a1" : sprsScore >= 50 ? "#f9e2af" : "#f38ba8";
        sb.AppendLine($"<div class=\"score-card\"><div class=\"score-grade\" style=\"color:{sprsColor};font-size:48px\">{sprsScore}</div><div class=\"score-value\">of 110</div><div class=\"score-label\">SPRS Score ({sprsConf})</div></div>");

        var passCount = checkList.Count(c => c.Status == CheckStatus.Pass);
        var failCount = checkList.Count(c => c.Status == CheckStatus.Fail);
        var partialCount = checkList.Count(c => c.Status == CheckStatus.Partial);
        var naCount = checkList.Count(c => c.Status is CheckStatus.NA or CheckStatus.NotAssessed);

        sb.AppendLine("<div class=\"score-card\">");
        sb.AppendLine($"<div class=\"stat-row\"><span class=\"dot pass\"></span> Pass: {passCount}</div>");
        sb.AppendLine($"<div class=\"stat-row\"><span class=\"dot partial\"></span> Partial: {partialCount}</div>");
        sb.AppendLine($"<div class=\"stat-row\"><span class=\"dot fail\"></span> Fail: {failCount}</div>");
        sb.AppendLine($"<div class=\"stat-row\"><span class=\"dot na\"></span> N/A: {naCount}</div>");
        sb.AppendLine("<div class=\"score-label\">Status Breakdown</div>");
        sb.AppendLine("</div>");
        sb.AppendLine("</div>");

        // Category Breakdown
        sb.AppendLine("<h2>Score by Category</h2>");
        sb.AppendLine("<table class=\"category-table\">");
        sb.AppendLine("<tr><th>Category</th><th>Pass</th><th>Partial</th><th>Fail</th><th>N/A</th></tr>");
        foreach (var group in checkList.GroupBy(c => c.Category).OrderBy(g => g.Key))
        {
            var gPass = group.Count(c => c.Status == CheckStatus.Pass);
            var gPartial = group.Count(c => c.Status == CheckStatus.Partial);
            var gFail = group.Count(c => c.Status == CheckStatus.Fail);
            var gNa = group.Count(c => c.Status is CheckStatus.NA or CheckStatus.NotAssessed);
            sb.AppendLine($"<tr><td>{group.Key}</td><td class=\"pass-cell\">{gPass}</td><td class=\"partial-cell\">{gPartial}</td><td class=\"fail-cell\">{gFail}</td><td>{gNa}</td></tr>");
        }
        sb.AppendLine("</table>");

        // Detailed Findings
        sb.AppendLine("<h2>Detailed Findings</h2>");
        foreach (var group in checkList.GroupBy(c => c.Category).OrderBy(g => g.Key))
        {
            sb.AppendLine($"<h3>{group.Key}</h3>");
            sb.AppendLine("<table class=\"findings-table\">");
            sb.AppendLine("<tr><th>ID</th><th>Check</th><th>Severity</th><th>Status</th><th>ATT&amp;CK</th><th>Findings</th><th>Evidence</th></tr>");
            foreach (var check in group.OrderBy(c => c.Id))
            {
                var severityClass = check.Severity.ToString().ToLowerInvariant();
                var statusClass = check.Status.ToString().ToLowerInvariant();
                var mitre = MitreMappings.All.GetValueOrDefault(check.Id);
                var mitreCell = mitre is not null
                    ? string.Join(", ", mitre.Techniques.Select(t => $"<span class=\"badge severity-medium\">{t}</span>"))
                    : "";
                sb.AppendLine($"<tr>");
                sb.AppendLine($"<td class=\"id-cell\">{check.Id}</td>");
                sb.AppendLine($"<td>{EscapeHtml(check.Label)}{(check.RemediationUrl is not null ? $" <a href=\"{check.RemediationUrl}\" style=\"color:#89b4fa;font-size:11px\">[remediation]</a>" : "")}</td>");
                sb.AppendLine($"<td><span class=\"badge severity-{severityClass}\">{check.SeverityLabel}</span></td>");
                sb.AppendLine($"<td><span class=\"badge status-{statusClass}\">{check.Status}</span></td>");
                sb.AppendLine($"<td class=\"mitre-cell\">{mitreCell}</td>");
                sb.AppendLine($"<td class=\"findings-cell\">{EscapeHtml(check.Findings)}</td>");
                sb.AppendLine($"<td class=\"evidence-cell\">{EscapeHtml(check.Evidence)}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        // Per-framework compliance scores
        sb.AppendLine("<h2>Compliance Framework Coverage</h2>");
        sb.AppendLine("<table class=\"category-table\">");
        sb.AppendLine("<tr><th>Framework</th><th>Mapped Checks</th><th>Passing</th><th>Coverage</th></tr>");
        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);
        foreach (var (fwName, sel) in FrameworkDefinitions.All)
        {
            var mapped = FrameworkMappings.All.Where(kv => sel(kv.Value) is not null).Select(kv => kv.Key).ToList();
            int fwTotal = 0, fwPass = 0;
            foreach (var cid in mapped)
            {
                if (!statusLookup.TryGetValue(cid, out var st) || st is CheckStatus.NA or CheckStatus.NotAssessed) continue;
                fwTotal++;
                if (st is CheckStatus.Pass or CheckStatus.Partial) fwPass++;
            }
            var pct = fwTotal > 0 ? Math.Round((double)fwPass / fwTotal * 100) : 0;
            var color = pct >= 80 ? "#a6e3a1" : pct >= 60 ? "#f9e2af" : "#f38ba8";
            sb.AppendLine($"<tr><td>{fwName}</td><td>{mapped.Count}</td><td class=\"pass-cell\">{fwPass}/{fwTotal}</td><td style=\"color:{color};font-weight:600\">{pct}%</td></tr>");
        }
        sb.AppendLine("</table>");

        // Detailed compliance per check
        sb.AppendLine("<h3>Per-Check Framework Control IDs</h3>");
        sb.AppendLine("<table class=\"compliance-table\">");
        sb.AppendLine("<tr><th>Check ID</th><th>Label</th><th>Framework Controls</th></tr>");
        foreach (var check in checkList.OrderBy(c => c.Id))
        {
            var mapping = FrameworkMappings.All.GetValueOrDefault(check.Id);
            var controls = mapping?.FormatAll() ?? "";
            if (string.IsNullOrWhiteSpace(controls)) continue;
            sb.AppendLine($"<tr><td>{check.Id}</td><td>{EscapeHtml(check.Label)}</td><td style=\"font-size:12px\">{EscapeHtml(controls)}</td></tr>");
        }
        sb.AppendLine("</table>");

        // D3FEND Coverage
        sb.AppendLine("<h2>MITRE D3FEND Defensive Coverage</h2>");
        sb.AppendLine("<table class=\"category-table\">");
        sb.AppendLine("<tr><th>Stage</th><th>Checks</th><th>Techniques</th></tr>");
        var stageChecks = new Dictionary<string, List<(string id, string[] techniques)>>();
        foreach (var check in checkList)
        {
            var defend = D3FendMappings.All.GetValueOrDefault(check.Id);
            if (defend is null) continue;
            foreach (var stage in defend.Stages)
            {
                if (!stageChecks.ContainsKey(stage))
                    stageChecks[stage] = [];
                stageChecks[stage].Add((check.Id, defend.Techniques));
            }
        }
        foreach (var (stage, checks2) in stageChecks.OrderBy(kv => kv.Key))
        {
            var allTechniques = checks2.SelectMany(c => c.techniques).Distinct().OrderBy(t => t).ToList();
            sb.AppendLine($"<tr><td style=\"font-weight:600\">{stage}</td><td>{checks2.Count}</td><td style=\"font-size:12px\">{EscapeHtml(string.Join(", ", allTechniques))}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine($"<div class=\"footer\">Network Security Auditor v{VersionInfo.Version}</div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static string GradeColor(string grade) => grade switch
    {
        "A" => "#a6e3a1",
        "B" => "#94e2d5",
        "C" => "#f9e2af",
        "D" => "#fab387",
        "F" => "#f38ba8",
        _ => "#9399b2"
    };

    private static string EscapeHtml(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("\n", "<br>");
    }

    private static string GetCss() => """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #1e1e2e; color: #cdd6f4;
            line-height: 1.6; padding: 32px;
        }
        .header {
            background: #313244; border-radius: 8px; padding: 32px;
            margin-bottom: 24px; border-left: 4px solid #cba6f7;
        }
        .header h1 { color: #cba6f7; font-size: 28px; margin-bottom: 8px; }
        .subtitle { color: #b5bcd6; font-size: 14px; }
        h2 { color: #cba6f7; margin: 24px 0 12px; font-size: 20px; }
        h3 { color: #b5bcd6; margin: 16px 0 8px; font-size: 16px; }
        .summary-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px; margin-bottom: 24px;
        }
        .score-card {
            background: #313244; border-radius: 8px; padding: 24px;
            text-align: center;
        }
        .score-grade { font-size: 64px; font-weight: 700; }
        .score-value { font-size: 24px; color: #b5bcd6; margin: 4px 0; }
        .score-label { font-size: 13px; color: #7f839b; text-transform: uppercase; letter-spacing: 1px; }
        .stat-row { text-align: left; padding: 4px 0; font-size: 15px; }
        .dot {
            display: inline-block; width: 10px; height: 10px;
            border-radius: 50%; margin-right: 8px;
        }
        .dot.pass { background: #a6e3a1; }
        .dot.partial { background: #f9e2af; }
        .dot.fail { background: #f38ba8; }
        .dot.na { background: #585b70; }
        table {
            width: 100%; border-collapse: collapse;
            background: #313244; border-radius: 8px; overflow: hidden;
            margin-bottom: 16px;
        }
        th {
            background: #45475a; color: #cba6f7; text-align: left;
            padding: 10px 14px; font-size: 13px; text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        td { padding: 10px 14px; border-top: 1px solid #45475a; font-size: 14px; }
        tr:hover { background: #3b3d50; }
        .id-cell { font-family: 'Cascadia Code', monospace; color: #cba6f7; font-weight: 600; }
        .pass-cell { color: #a6e3a1; font-weight: 600; }
        .partial-cell { color: #f9e2af; font-weight: 600; }
        .fail-cell { color: #f38ba8; font-weight: 600; }
        .findings-cell, .evidence-cell { max-width: 300px; word-wrap: break-word; font-size: 13px; color: #b5bcd6; }
        .mitre-cell { max-width: 200px; font-size: 11px; }
        .badge {
            display: inline-block; padding: 2px 10px; border-radius: 6px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .severity-critical { background: rgba(243,139,168,0.2); color: #f38ba8; }
        .severity-high { background: rgba(250,179,135,0.2); color: #fab387; }
        .severity-medium { background: rgba(249,226,175,0.2); color: #f9e2af; }
        .severity-low { background: rgba(166,227,161,0.2); color: #a6e3a1; }
        .status-pass { background: rgba(166,227,161,0.2); color: #a6e3a1; }
        .status-partial { background: rgba(249,226,175,0.2); color: #f9e2af; }
        .status-fail { background: rgba(243,139,168,0.2); color: #f38ba8; }
        .status-na { background: rgba(147,153,178,0.2); color: #9399b2; }
        .status-notassessed { background: rgba(88,91,112,0.2); color: #585b70; }
        .footer {
            text-align: center; padding: 24px; color: #585b70;
            font-size: 12px; margin-top: 32px;
        }
        @media (max-width: 768px) {
            body { padding: 12px; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .score-grade { font-size: 48px; }
            .findings-cell, .evidence-cell { max-width: 200px; }
            .mitre-cell { display: none; }
        }
        @media (max-width: 480px) {
            .summary-grid { grid-template-columns: 1fr; }
            .header { padding: 16px; }
            .header h1 { font-size: 22px; }
            table { display: block; overflow-x: auto; white-space: nowrap; }
            th, td { padding: 6px 8px; font-size: 12px; }
            .findings-cell, .evidence-cell { max-width: 150px; white-space: normal; }
        }
        @media print {
            body { background: #fff; color: #333; padding: 16px; }
            .header { background: #f5f5f5; border-left-color: #7c3aed; }
            .header h1 { color: #7c3aed; }
            .score-card { background: #f5f5f5; }
            table { background: #fff; }
            th { background: #eee; color: #7c3aed; }
            td { border-top-color: #ddd; }
            .findings-cell, .evidence-cell, .subtitle { color: #666; }
        }
        """;
}

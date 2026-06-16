using System.Text;
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
        string ransomwareGrade)
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
            sb.AppendLine("<tr><th>ID</th><th>Check</th><th>Severity</th><th>Status</th><th>Findings</th><th>Evidence</th></tr>");
            foreach (var check in group.OrderBy(c => c.Id))
            {
                var severityClass = check.Severity.ToString().ToLowerInvariant();
                var statusClass = check.Status.ToString().ToLowerInvariant();
                sb.AppendLine($"<tr>");
                sb.AppendLine($"<td class=\"id-cell\">{check.Id}</td>");
                sb.AppendLine($"<td>{check.Label}</td>");
                sb.AppendLine($"<td><span class=\"badge severity-{severityClass}\">{check.SeverityLabel}</span></td>");
                sb.AppendLine($"<td><span class=\"badge status-{statusClass}\">{check.Status}</span></td>");
                sb.AppendLine($"<td class=\"findings-cell\">{EscapeHtml(check.Findings)}</td>");
                sb.AppendLine($"<td class=\"evidence-cell\">{EscapeHtml(check.Evidence)}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        // Compliance
        sb.AppendLine("<h2>Compliance Framework Coverage</h2>");
        sb.AppendLine("<table class=\"compliance-table\">");
        sb.AppendLine("<tr><th>Check ID</th><th>Label</th><th>Compliance Mappings</th></tr>");
        foreach (var check in checkList.Where(c => !string.IsNullOrWhiteSpace(c.Compliance)).OrderBy(c => c.Id))
        {
            sb.AppendLine($"<tr><td>{check.Id}</td><td>{check.Label}</td><td>{EscapeHtml(check.Compliance)}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("<div class=\"footer\">Network Security Auditor v5.0.0</div>");
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
            display: grid; grid-template-columns: repeat(3, 1fr);
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

using System.IO;
using System.Text;
using System.Text.Json;

namespace NetworkSecurityAuditor.Export;

public static class DashboardGenerator
{
    public static async Task<string> GenerateAsync(string inputDir, int staleDays = 30)
    {
        var jsonFiles = Directory.GetFiles(inputDir, "*_findings.json", SearchOption.TopDirectoryOnly);
        var clients = new List<ClientSummary>();

        foreach (var file in jsonFiles.OrderBy(f => f))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var client = new ClientSummary
                {
                    FileName = Path.GetFileName(file),
                    FilePath = file,
                    Timestamp = root.TryGetProperty("timestamp", out var ts) ? ts.GetString() ?? "" : "",
                    Client = root.TryGetProperty("client", out var cl) ? cl.GetString() ?? "" : Path.GetFileNameWithoutExtension(file),
                    Host = root.TryGetProperty("environment", out var env) && env.TryGetProperty("computer_name", out var cn) ? cn.GetString() ?? "" : "",
                    OS = root.TryGetProperty("environment", out var env2) && env2.TryGetProperty("os_caption", out var os) ? os.GetString() ?? "" : ""
                };

                if (root.TryGetProperty("score", out var score))
                {
                    client.OverallScore = score.TryGetProperty("overall", out var ov) ? ov.GetInt32() : 0;
                    client.Grade = score.TryGetProperty("grade", out var gr) ? gr.GetString() ?? "" : "";
                    client.RansomwareScore = score.TryGetProperty("ransomware_readiness", out var rw) ? rw.GetInt32() : 0;
                    client.RansomwareGrade = score.TryGetProperty("ransomware_grade", out var rwg) ? rwg.GetString() ?? "" : "";
                    client.DomainMaturityScore = score.TryGetProperty("domain_maturity", out var dm) ? dm.GetInt32() : 0;
                }

                if (root.TryGetProperty("findings", out var findings))
                {
                    foreach (var f in findings.EnumerateArray())
                    {
                        var status = f.TryGetProperty("status", out var st) ? st.GetString() : "";
                        var severity = f.TryGetProperty("severity", out var sv) ? sv.GetString() : "";
                        if (status == "fail" || status == "Fail") client.FailCount++;
                        if ((status == "fail" || status == "Fail") && (severity == "critical" || severity == "Critical"))
                            client.CriticalCount++;
                    }
                }

                if (DateTime.TryParse(client.Timestamp, out var scanDate))
                    client.IsStale = (DateTime.UtcNow - scanDate).TotalDays > staleDays;

                var htmlSibling = Path.ChangeExtension(file, ".html")
                    .Replace("_findings.html", ".html");
                if (File.Exists(htmlSibling))
                    client.ReportPath = Path.GetFileName(htmlSibling);

                clients.Add(client);
            }
            catch { }
        }

        return BuildHtml(clients, staleDays);
    }

    public static async Task<string> GenerateCsvAsync(string inputDir, int staleDays = 30)
    {
        var jsonFiles = Directory.GetFiles(inputDir, "*_findings.json", SearchOption.TopDirectoryOnly);
        var sb = new StringBuilder();
        sb.AppendLine("Client,Host,OS,Score,Grade,Ransomware,CriticalFails,TotalFails,Stale,ScanDate,File");

        foreach (var file in jsonFiles.OrderBy(f => f))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var client = root.TryGetProperty("client", out var cl) ? cl.GetString() ?? "" : "";
                var host = root.TryGetProperty("environment", out var env) && env.TryGetProperty("computer_name", out var cn) ? cn.GetString() ?? "" : "";
                var os = root.TryGetProperty("environment", out var env2) && env2.TryGetProperty("os_caption", out var osc) ? osc.GetString() ?? "" : "";
                var score = root.TryGetProperty("score", out var sc) && sc.TryGetProperty("overall", out var ov) ? ov.GetInt32() : 0;
                var grade = root.TryGetProperty("score", out var sc2) && sc2.TryGetProperty("grade", out var gr) ? gr.GetString() ?? "" : "";
                var rw = root.TryGetProperty("score", out var sc3) && sc3.TryGetProperty("ransomware_readiness", out var rwv) ? rwv.GetInt32() : 0;
                var timestamp = root.TryGetProperty("timestamp", out var ts) ? ts.GetString() ?? "" : "";
                int failCount = 0, critCount = 0;
                if (root.TryGetProperty("findings", out var findings))
                {
                    foreach (var f in findings.EnumerateArray())
                    {
                        var status = f.TryGetProperty("status", out var st) ? st.GetString() : "";
                        var sev = f.TryGetProperty("severity", out var sv) ? sv.GetString() : "";
                        if (status == "fail" || status == "Fail") failCount++;
                        if ((status == "fail" || status == "Fail") && (sev == "critical" || sev == "Critical")) critCount++;
                    }
                }
                var stale = DateTime.TryParse(timestamp, out var d) && (DateTime.UtcNow - d).TotalDays > staleDays;

                sb.AppendLine($"{CsvEsc(client)},{CsvEsc(host)},{CsvEsc(os)},{score},{CsvEsc(grade)},{rw},{critCount},{failCount},{stale},{CsvEsc(timestamp)},{CsvEsc(Path.GetFileName(file))}");
            }
            catch { }
        }
        return sb.ToString();
    }

    private static string BuildHtml(List<ClientSummary> clients, int staleDays)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("<title>Security Audit Dashboard</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("""
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 32px; }
            h1 { color: #cba6f7; margin-bottom: 8px; }
            .subtitle { color: #7f839b; font-size: 14px; margin-bottom: 24px; }
            .summary-bar { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
            .summary-stat { background: #313244; border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 140px; }
            .summary-stat .value { font-size: 32px; font-weight: 700; }
            .summary-stat .label { font-size: 11px; color: #7f839b; text-transform: uppercase; letter-spacing: 1px; }
            table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 8px; overflow: hidden; }
            th { background: #45475a; color: #cba6f7; text-align: left; padding: 10px 14px; font-size: 13px; text-transform: uppercase; }
            td { padding: 10px 14px; border-top: 1px solid #45475a; font-size: 14px; }
            tr:hover { background: #3b3d50; }
            .grade-a { color: #a6e3a1; } .grade-b { color: #94e2d5; } .grade-c { color: #f9e2af; }
            .grade-d { color: #fab387; } .grade-f { color: #f38ba8; }
            .stale { color: #f38ba8; font-weight: 600; }
            .footer { text-align: center; padding: 24px; color: #585b70; font-size: 12px; margin-top: 32px; }
            a { color: #89b4fa; text-decoration: none; } a:hover { text-decoration: underline; }
            @media (max-width: 768px) { body { padding: 12px; } .summary-bar { flex-direction: column; } }
            """);
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Multi-Client Security Dashboard</h1>");
        sb.AppendLine($"<p class=\"subtitle\">Generated {Esc(DateTime.Now.ToString("yyyy-MM-dd HH:mm"))} | {clients.Count} clients | Stale threshold: {staleDays} days</p>");

        var avgScore = clients.Count > 0 ? clients.Average(c => c.OverallScore) : 0;
        var totalCritical = clients.Sum(c => c.CriticalCount);
        var staleCount = clients.Count(c => c.IsStale);

        sb.AppendLine("<div class=\"summary-bar\">");
        sb.AppendLine($"<div class=\"summary-stat\"><div class=\"value\">{clients.Count}</div><div class=\"label\">Clients</div></div>");
        sb.AppendLine($"<div class=\"summary-stat\"><div class=\"value\">{avgScore:F0}%</div><div class=\"label\">Avg Score</div></div>");
        sb.AppendLine($"<div class=\"summary-stat\"><div class=\"value\" style=\"color:#f38ba8\">{totalCritical}</div><div class=\"label\">Critical Findings</div></div>");
        sb.AppendLine($"<div class=\"summary-stat\"><div class=\"value\"{(staleCount > 0 ? " style=\"color:#f38ba8\"" : "")}>{staleCount}</div><div class=\"label\">Stale Scans</div></div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>Client</th><th>Host</th><th>Score</th><th>Grade</th><th>Ransomware</th><th>Critical</th><th>Fails</th><th>Scan Date</th><th>Report</th></tr>");

        foreach (var c in clients.OrderByDescending(c => c.CriticalCount).ThenBy(c => c.OverallScore))
        {
            var gradeClass = $"grade-{c.Grade.ToLowerInvariant()}";
            var dateDisplay = DateTime.TryParse(c.Timestamp, out var d) ? d.ToString("yyyy-MM-dd") : "N/A";
            var staleFlag = c.IsStale ? " <span class=\"stale\">[STALE]</span>" : "";
            var reportLink = c.ReportPath is not null ? $"<a href=\"{c.ReportPath}\">View</a>" : "";

            sb.AppendLine($"<tr>");
            sb.AppendLine($"<td>{Esc(c.Client)}</td>");
            sb.AppendLine($"<td>{Esc(c.Host)} <span style=\"font-size:11px;color:#7f839b\">{Esc(c.OS)}</span></td>");
            sb.AppendLine($"<td>{c.OverallScore}%</td>");
            sb.AppendLine($"<td class=\"{gradeClass}\" style=\"font-size:20px;font-weight:700\">{Esc(c.Grade)}</td>");
            sb.AppendLine($"<td>{c.RansomwareScore}%</td>");
            sb.AppendLine($"<td style=\"color:{(c.CriticalCount > 0 ? "#f38ba8" : "#a6e3a1")}\">{c.CriticalCount}</td>");
            sb.AppendLine($"<td>{c.FailCount}</td>");
            sb.AppendLine($"<td>{Esc(dateDisplay)}{staleFlag}</td>");
            sb.AppendLine($"<td>{reportLink}</td>");
            sb.AppendLine("</tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine($"<div class=\"footer\">Network Security Auditor v{VersionInfo.Version} - Dashboard</div>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    private static string Esc(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string CsvEsc(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private sealed class ClientSummary
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public string Client { get; set; } = "";
        public string Host { get; set; } = "";
        public string OS { get; set; } = "";
        public int OverallScore { get; set; }
        public string Grade { get; set; } = "";
        public int RansomwareScore { get; set; }
        public string RansomwareGrade { get; set; } = "";
        public int DomainMaturityScore { get; set; }
        public int FailCount { get; set; }
        public int CriticalCount { get; set; }
        public bool IsStale { get; set; }
        public string? ReportPath { get; set; }
    }
}

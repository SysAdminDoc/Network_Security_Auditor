using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace NetworkSecurityAuditor.Export;

public static class DashboardGenerator
{
    public static async Task<string> GenerateAsync(string inputDir, int staleDays = 30)
    {
        var data = await LoadDashboardDataAsync(inputDir, staleDays);
        return BuildHtml(data.Clients, staleDays, data.SkippedFiles, data.DuplicateFiles);
    }

    public static async Task<string> GenerateCsvAsync(string inputDir, int staleDays = 30)
    {
        var data = await LoadDashboardDataAsync(inputDir, staleDays);
        var sb = new StringBuilder();
        sb.AppendLine("Client,Host,OS,Score,Grade,Ransomware,CriticalFails,TotalFails,Stale,ScanDate,File,Trend,DuplicateFiles");

        foreach (var client in SortDashboardRows(data.Clients))
        {
            sb.AppendLine(
                $"{CsvEsc(client.Client)},{CsvEsc(client.Host)},{CsvEsc(client.OS)},{client.OverallScore},{CsvEsc(client.Grade)},{client.RansomwareScore},{client.CriticalCount},{client.FailCount},{client.IsStale},{CsvEsc(client.Timestamp)},{CsvEsc(client.FileName)},{CsvEsc(FormatTrend(client.Trend))},{CsvEsc(string.Join("|", client.DuplicateFiles))}");
        }

        foreach (var skipped in data.SkippedFiles.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"# SKIPPED: {CsvEsc(skipped.FileName)} - {CsvEsc(skipped.Reason)}");
        }

        foreach (var duplicate in data.DuplicateFiles.OrderBy(d => d.FileName, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"# DUPLICATE: {CsvEsc(duplicate.FileName)} - latest for {CsvEsc(duplicate.StableKey)} is {CsvEsc(duplicate.LatestFileName)}");
        }

        return sb.ToString();
    }

    private static async Task<DashboardData> LoadDashboardDataAsync(string inputDir, int staleDays)
    {
        var jsonFiles = Directory.GetFiles(inputDir, "*_findings.json", SearchOption.TopDirectoryOnly);
        var parsed = new List<ClientSummary>();
        var data = new DashboardData();

        foreach (var file in jsonFiles.OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                parsed.Add(ParseClientSummary(file, json, staleDays));
            }
            catch (Exception ex)
            {
                data.SkippedFiles.Add(new SkippedFile(Path.GetFileName(file), ex.Message));
            }
        }

        foreach (var group in parsed.GroupBy(c => c.StableKey, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group
                .OrderBy(c => c.ScanTime ?? DateTimeOffset.MinValue)
                .ThenBy(c => c.FileName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var latest = ordered
                .OrderByDescending(c => c.ScanTime ?? DateTimeOffset.MinValue)
                .ThenBy(c => c.FileName, StringComparer.OrdinalIgnoreCase)
                .First();

            latest.Trend = ordered
                .Select(c => new TrendPoint(TrendTimestamp(c), c.OverallScore))
                .ToList();
            latest.DuplicateFiles = ordered
                .Where(c => !ReferenceEquals(c, latest))
                .Select(c => c.FileName)
                .ToList();

            foreach (var duplicate in latest.DuplicateFiles)
            {
                data.DuplicateFiles.Add(new DuplicateScan(duplicate, latest.StableKey, latest.FileName));
            }

            data.Clients.Add(latest);
        }

        return data;
    }

    private static ClientSummary ParseClientSummary(string file, string json, int staleDays)
    {
        using var doc = JsonDocument.Parse(json);
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
            foreach (var finding in findings.EnumerateArray())
            {
                var status = finding.TryGetProperty("status", out var st) ? st.GetString() : "";
                var severity = finding.TryGetProperty("severity", out var sv) ? sv.GetString() : "";
                if (string.Equals(status, "fail", StringComparison.OrdinalIgnoreCase)) client.FailCount++;
                if (string.Equals(status, "fail", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase))
                    client.CriticalCount++;
            }
        }

        client.ScanTime = ParseTimestamp(client.Timestamp);
        client.IsStale = client.ScanTime is not null && (DateTimeOffset.UtcNow - client.ScanTime.Value).TotalDays > staleDays;
        client.StableKey = BuildStableKey(client);

        var htmlSibling = Path.ChangeExtension(file, ".html")
            .Replace("_findings.html", ".html", StringComparison.OrdinalIgnoreCase);
        if (File.Exists(htmlSibling))
            client.ReportPath = Path.GetFileName(htmlSibling);

        return client;
    }

    private static string BuildHtml(
        List<ClientSummary> clients,
        int staleDays,
        List<SkippedFile> skippedFiles,
        List<DuplicateScan> duplicateFiles)
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
            .subtitle { color: #a6adc8; font-size: 14px; margin-bottom: 24px; }
            .summary-bar { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
            .summary-stat { background: #313244; border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 140px; }
            .summary-stat .value { font-size: 32px; font-weight: 700; }
            .summary-stat .label { font-size: 11px; color: #a6adc8; text-transform: uppercase; letter-spacing: 1px; }
            table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 8px; overflow: hidden; }
            th { background: #45475a; color: #cba6f7; text-align: left; padding: 10px 14px; font-size: 13px; text-transform: uppercase; }
            td { padding: 10px 14px; border-top: 1px solid #45475a; font-size: 14px; vertical-align: middle; }
            tr:hover { background: #3b3d50; }
            .grade-a { color: #a6e3a1; } .grade-b { color: #94e2d5; } .grade-c { color: #f9e2af; }
            .grade-d { color: #fab387; } .grade-f { color: #f38ba8; }
            .stale { color: #f38ba8; font-weight: 600; }
            .trend { width: 96px; height: 24px; overflow: visible; margin-right: 6px; vertical-align: middle; }
            .trend-line { fill: none; stroke: #89b4fa; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
            .trend-data { color: #a6adc8; font-size: 12px; white-space: nowrap; }
            .footer { text-align: center; padding: 24px; color: #7f849c; font-size: 12px; margin-top: 32px; }
            a { color: #89b4fa; text-decoration: none; } a:hover { text-decoration: underline; }
            @media (max-width: 768px) { body { padding: 12px; } .summary-bar { flex-direction: column; } table { display: block; overflow-x: auto; } }
            """);
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Multi-Client Security Dashboard</h1>");
        sb.AppendLine($"<p class=\"subtitle\">Generated {Esc(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))} UTC | {clients.Count} clients | Stale threshold: {staleDays} days | {duplicateFiles.Count} older scan(s) hidden</p>");

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
        sb.AppendLine("<tr><th>Client</th><th>Host</th><th>Score</th><th>Grade</th><th>Trend</th><th>Ransomware</th><th>Critical</th><th>Fails</th><th>Scan Date</th><th>Report</th></tr>");

        foreach (var c in SortDashboardRows(clients))
        {
            var gradeClass = GradeCssClass(c.Grade);
            var dateDisplay = DisplayDate(c);
            var staleFlag = c.IsStale ? " <span class=\"stale\">[STALE]</span>" : "";
            var reportLink = c.ReportPath is not null ? $"<a href=\"{Esc(c.ReportPath)}\">View</a>" : "";

            sb.AppendLine("<tr>");
            sb.AppendLine($"<td>{Esc(c.Client)}</td>");
            sb.AppendLine($"<td>{Esc(c.Host)} <span style=\"font-size:11px;color:#a6adc8\">{Esc(c.OS)}</span></td>");
            sb.AppendLine($"<td>{c.OverallScore}%</td>");
            sb.AppendLine($"<td class=\"{gradeClass}\" style=\"font-size:20px;font-weight:700\">{Esc(c.Grade)}</td>");
            sb.AppendLine($"<td>{BuildTrendSparkline(c.Trend)}</td>");
            sb.AppendLine($"<td>{c.RansomwareScore}%</td>");
            sb.AppendLine($"<td style=\"color:{(c.CriticalCount > 0 ? "#f38ba8" : "#a6e3a1")}\">{c.CriticalCount}</td>");
            sb.AppendLine($"<td>{c.FailCount}</td>");
            sb.AppendLine($"<td>{Esc(dateDisplay)}{staleFlag}</td>");
            sb.AppendLine($"<td>{reportLink}</td>");
            sb.AppendLine("</tr>");
        }
        sb.AppendLine("</table>");

        if (duplicateFiles.Count > 0)
        {
            sb.AppendLine($"<p style=\"color:#f9e2af;margin-top:16px;font-size:13px\">{duplicateFiles.Count} older duplicate scan(s) hidden from the latest-client table:</p>");
            sb.AppendLine("<ul style=\"color:#a6adc8;font-size:12px;margin-top:4px\">");
            foreach (var duplicate in duplicateFiles.OrderBy(d => d.FileName, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"<li>{Esc(duplicate.FileName)}: latest for {Esc(duplicate.StableKey)} is {Esc(duplicate.LatestFileName)}</li>");
            sb.AppendLine("</ul>");
        }

        if (skippedFiles.Count > 0)
        {
            sb.AppendLine($"<p style=\"color:#f38ba8;margin-top:16px;font-size:13px\">{skippedFiles.Count} file(s) could not be parsed:</p>");
            sb.AppendLine("<ul style=\"color:#a6adc8;font-size:12px;margin-top:4px\">");
            foreach (var skipped in skippedFiles.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"<li>{Esc(skipped.FileName)}: {Esc(skipped.Reason)}</li>");
            sb.AppendLine("</ul>");
        }

        sb.AppendLine($"<div class=\"footer\">Network Security Auditor v{VersionInfo.Version} - Dashboard</div>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    private static IEnumerable<ClientSummary> SortDashboardRows(IEnumerable<ClientSummary> clients) =>
        clients.OrderByDescending(c => c.CriticalCount)
            .ThenBy(c => c.OverallScore)
            .ThenBy(c => c.Client, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Host, StringComparer.OrdinalIgnoreCase);

    private static string BuildStableKey(ClientSummary client)
    {
        var clientKey = string.IsNullOrWhiteSpace(client.Client)
            ? Path.GetFileNameWithoutExtension(client.FileName)
            : client.Client;
        var hostKey = string.IsNullOrWhiteSpace(client.Host) ? "(unknown-host)" : client.Host;
        return $"{NormalizeKey(clientKey)}|{NormalizeKey(hostKey)}";
    }

    private static string NormalizeKey(string value) => value.Trim().ToUpperInvariant();

    private static DateTimeOffset? ParseTimestamp(string timestamp)
    {
        if (DateTimeOffset.TryParse(
            timestamp,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var offset))
            return offset;

        return null;
    }

    private static string DisplayDate(ClientSummary client) =>
        client.ScanTime?.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
        ?? (string.IsNullOrWhiteSpace(client.Timestamp) ? "N/A" : client.Timestamp);

    private static string TrendTimestamp(ClientSummary client) =>
        string.IsNullOrWhiteSpace(client.Timestamp) ? client.FileName : client.Timestamp;

    private static string FormatTrend(IReadOnlyList<TrendPoint> trend) =>
        string.Join("|", trend.Select(p => $"{p.Timestamp}:{p.Score}"));

    private static string BuildTrendSparkline(IReadOnlyList<TrendPoint> trend)
    {
        if (trend.Count == 0)
            return "";

        var title = Esc(FormatTrend(trend));
        if (trend.Count == 1)
            return $"<span class=\"trend-data\" title=\"{title}\">{trend[0].Score}%</span>";

        const double width = 96;
        const double height = 24;
        var maxIndex = Math.Max(1, trend.Count - 1);
        var points = trend
            .Select((point, index) =>
            {
                var x = index * width / maxIndex;
                var y = height - Math.Clamp(point.Score, 0, 100) * height / 100;
                return FormattableString.Invariant($"{x:F1},{y:F1}");
            });
        var label = $"{trend.First().Score}% -> {trend.Last().Score}%";

        return $"<svg class=\"trend\" viewBox=\"0 0 {width:0} {height:0}\" role=\"img\" aria-label=\"{title}\"><polyline class=\"trend-line\" points=\"{string.Join(' ', points)}\" /></svg><span class=\"trend-data\">{Esc(label)}</span>";
    }

    private static string Esc(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string CsvEsc(string? value)
    {
        return CsvExporter.Escape(value);
    }

    private static string GradeCssClass(string? grade)
    {
        var trimmed = grade?.Trim();
        if (trimmed is { Length: 1 } &&
            (trimmed[0] is 'A' or 'a' or 'B' or 'b' or 'C' or 'c' or 'D' or 'd' or 'E' or 'e' or 'F' or 'f'))
        {
            return $"grade-{char.ToLowerInvariant(trimmed[0])}";
        }

        return "grade-unknown";
    }

    private sealed class DashboardData
    {
        public List<ClientSummary> Clients { get; } = [];
        public List<SkippedFile> SkippedFiles { get; } = [];
        public List<DuplicateScan> DuplicateFiles { get; } = [];
    }

    private sealed record SkippedFile(string FileName, string Reason);

    private sealed record DuplicateScan(string FileName, string StableKey, string LatestFileName);

    private sealed record TrendPoint(string Timestamp, int Score);

    private sealed class ClientSummary
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string StableKey { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public DateTimeOffset? ScanTime { get; set; }
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
        public List<TrendPoint> Trend { get; set; } = [];
        public List<string> DuplicateFiles { get; set; } = [];
    }
}

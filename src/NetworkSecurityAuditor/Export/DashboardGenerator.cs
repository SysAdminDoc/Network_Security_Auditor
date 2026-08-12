using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using NetworkSecurityAuditor.Localization;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Export;

public static class DashboardGenerator
{
    internal const long MaxInputFileBytes = ImportFileGuard.MaxDashboardFileBytes;
    internal const long MaxInputTotalBytes = ImportFileGuard.MaxDashboardTotalBytes;
    internal const int MaxInputFiles = ImportFileGuard.MaxDashboardFiles;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static async Task<string> GenerateAsync(
        string inputDir,
        int staleDays = 30,
        DateTimeOffset? generatedAt = null)
    {
        var now = (generatedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var data = await LoadDashboardDataAsync(inputDir, staleDays, now);
        return BuildHtml(data, staleDays, now);
    }

    public static async Task<string> GenerateCsvAsync(
        string inputDir,
        int staleDays = 30,
        DateTimeOffset? generatedAt = null)
    {
        var now = (generatedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var data = await LoadDashboardDataAsync(inputDir, staleDays, now);
        var metrics = BuildMetrics(data);
        var sb = new StringBuilder();
        var header = new[]
        {
            "RecordType", "AssetsDiscovered", "AssetsValid", "AssetsScanned", "AssetsSkipped", "AssetsFailed",
            "CoveragePct", "CoverageDenominator", "FreshAssets", "StaleAssets", "FreshnessDenominator",
            "AverageScore", "MedianScore", "ScorePopulation", "OpenCriticals", "NewCriticals", "ResolvedCriticals",
            "CriticalChangeDenominator", "OldestHighAgeDays", "OldestCriticalAgeDays", "ActiveExceptions",
            "ExpiredExceptions", "ExceptionDenominator", "RemediationDenominator", "RemediationNotDue",
            "RemediationOverdue1To30", "RemediationOverdue31To60", "RemediationOverdue61To90",
            "RemediationOverdue91Plus", "RemediationNoDueDate", "Client", "Host", "OS", "Score", "Grade",
            "Ransomware", "CriticalFails", "TotalFails", "Stale", "ScanDate", "File", "Trend", "DuplicateFiles"
        };
        AppendCsvRow(sb, header);

        AppendCsvRow(sb,
        [
            "Summary", I(metrics.AssetsDiscovered), I(metrics.AssetsValid), I(metrics.AssetsScanned),
            I(metrics.AssetsSkipped), I(metrics.AssetsFailed), D(metrics.CoveragePercentage), I(metrics.CoverageDenominator),
            I(metrics.FreshAssets), I(metrics.StaleAssets), I(metrics.FreshnessDenominator), D(metrics.AverageScore),
            D(metrics.MedianScore), I(metrics.ScorePopulation), I(metrics.OpenCriticals), I(metrics.NewCriticals),
            I(metrics.ResolvedCriticals), I(metrics.CriticalChangeDenominator), I(metrics.OldestHighAgeDays),
            I(metrics.OldestCriticalAgeDays), I(metrics.ActiveExceptions), I(metrics.ExpiredExceptions),
            I(metrics.ExceptionDenominator), I(metrics.RemediationDenominator), I(metrics.RemediationNotDue),
            I(metrics.RemediationOverdue1To30), I(metrics.RemediationOverdue31To60), I(metrics.RemediationOverdue61To90),
            I(metrics.RemediationOverdue91Plus), I(metrics.RemediationNoDueDate), "", "", "", "", "", "", "", "", "", "", "", "", ""
        ]);

        foreach (var client in SortDashboardRows(data.Clients))
        {
            AppendCsvRow(sb,
            [
                "Asset", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                client.Client, client.Host, client.OS, I(client.OverallScore), client.Grade, I(client.RansomwareScore),
                I(client.CriticalCount), I(client.FailCount), client.IsStale.ToString(CultureInfo.InvariantCulture),
                client.Timestamp, client.FileName, FormatTrend(client.Trend), string.Join("|", client.DuplicateFiles)
            ]);
        }

        foreach (var failed in data.FailedFiles.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine($"# FAILED: {CsvEsc(failed.FileName)} - {CsvEsc(failed.Reason)}");

        foreach (var skipped in data.SkippedAssets.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine($"# SKIPPED_ASSET: {CsvEsc(skipped.FileName)} - {CsvEsc(skipped.Reason)}");

        foreach (var duplicate in data.DuplicateFiles.OrderBy(d => d.FileName, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine($"# DUPLICATE: {CsvEsc(duplicate.FileName)} - latest for {CsvEsc(duplicate.StableKey)} is {CsvEsc(duplicate.LatestFileName)}");

        return sb.ToString();
    }

    public static async Task<string> GenerateJsonAsync(
        string inputDir,
        int staleDays = 30,
        DateTimeOffset? generatedAt = null)
    {
        var now = (generatedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var data = await LoadDashboardDataAsync(inputDir, staleDays, now);
        var metrics = BuildMetrics(data);

        var report = new
        {
            schema_version = "1.0",
            tool = "Network Security Auditor",
            tool_version = VersionInfo.Version,
            generated_at_utc = now.ToString("O", CultureInfo.InvariantCulture),
            stale_after_days = staleDays,
            assets_discovered = metrics.AssetsDiscovered,
            assets_valid = metrics.AssetsValid,
            assets_scanned = metrics.AssetsScanned,
            assets_skipped = metrics.AssetsSkipped,
            assets_failed = metrics.AssetsFailed,
            coverage = new
            {
                numerator = metrics.AssetsScanned,
                denominator = metrics.CoverageDenominator,
                percentage = metrics.CoveragePercentage,
                denominator_definition = "unique latest asset identities plus failed inputs whose identity could not be safely deduplicated"
            },
            freshness = new
            {
                fresh = metrics.FreshAssets,
                stale = metrics.StaleAssets,
                unknown = metrics.UnknownFreshnessAssets,
                denominator = metrics.FreshnessDenominator,
                stale_after_days = staleDays
            },
            scores = new
            {
                average = metrics.AverageScore,
                median = metrics.MedianScore,
                population = metrics.ScorePopulation,
                population_definition = "latest contract-valid assets with at least one Pass, Partial, or Fail finding"
            },
            critical_findings = new
            {
                open = metrics.OpenCriticals,
                open_denominator = metrics.AssetsScanned,
                @new = metrics.NewCriticals,
                resolved = metrics.ResolvedCriticals,
                change_denominator = metrics.CriticalChangeDenominator,
                oldest_high_age_days = metrics.OldestHighAgeDays,
                oldest_critical_age_days = metrics.OldestCriticalAgeDays,
                age_denominator = metrics.ExposureAgeDenominator
            },
            exceptions = new
            {
                active = metrics.ActiveExceptions,
                expired = metrics.ExpiredExceptions,
                denominator = metrics.ExceptionDenominator
            },
            remediation_aging = new
            {
                denominator = metrics.RemediationDenominator,
                not_due = metrics.RemediationNotDue,
                overdue_1_to_30_days = metrics.RemediationOverdue1To30,
                overdue_31_to_60_days = metrics.RemediationOverdue31To60,
                overdue_61_to_90_days = metrics.RemediationOverdue61To90,
                overdue_91_plus_days = metrics.RemediationOverdue91Plus,
                no_due_date = metrics.RemediationNoDueDate,
                denominator_definition = "open failed findings excluding accepted-risk and deferred exceptions"
            },
            assets = SortDashboardRows(data.Clients).Select(ToJsonRow).ToArray(),
            diagnostics = new
            {
                input_files_discovered = data.InputFilesDiscovered,
                valid_scan_files = data.ValidScans.Count,
                duplicate_scan_files = data.DuplicateFiles.Count,
                failed_input_files = data.FailedFiles.Select(f => new { file = f.FileName, reason = f.Reason }).ToArray(),
                skipped_assets = data.SkippedAssets.Select(s => new { file = s.FileName, reason = s.Reason }).ToArray()
            }
        };

        return JsonSerializer.Serialize(report, JsonOptions);
    }

    private static async Task<DashboardData> LoadDashboardDataAsync(
        string inputDir,
        int staleDays,
        DateTimeOffset now)
    {
        var data = new DashboardData { GeneratedAtDate = DateOnly.FromDateTime(now.UtcDateTime) };
        long totalBytes = 0;
        var files = Directory.EnumerateFiles(inputDir, "*_findings.json", SearchOption.TopDirectoryOnly)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        data.InputFilesDiscovered = files.Length;

        for (var index = 0; index < files.Length; index++)
        {
            var file = files[index];
            if (index >= MaxInputFiles)
            {
                data.FailedFiles.Add(new FailedFile(Path.GetFileName(file), $"Dashboard import is limited to {MaxInputFiles:N0} files."));
                continue;
            }

            try
            {
                var length = new FileInfo(file).Length;
                if (length > MaxInputFileBytes)
                    throw new InvalidDataException($"File exceeds the {MaxInputFileBytes:N0}-byte dashboard limit.");
                if (totalBytes > MaxInputTotalBytes - length)
                    throw new InvalidDataException($"Dashboard import exceeds the {MaxInputTotalBytes:N0}-byte aggregate limit.");

                totalBytes += length;
                var json = await File.ReadAllTextAsync(file);
                data.ValidScans.Add(ParseClientSummary(file, json, staleDays, now));
            }
            catch (Exception ex)
            {
                data.FailedFiles.Add(new FailedFile(Path.GetFileName(file), ex.Message));
            }
        }

        foreach (var group in data.ValidScans
                     .GroupBy(c => c.StableKey, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group
                .OrderBy(c => c.ScanTime)
                .ThenBy(c => c.FileName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var latest = ordered[^1];
            latest.Trend = ordered
                .Where(c => c.IsScorable)
                .Select(c => new TrendPoint(c.Timestamp, c.OverallScore))
                .ToList();
            latest.DuplicateFiles = ordered
                .Where(c => !ReferenceEquals(c, latest))
                .Select(c => c.FileName)
                .ToList();

            foreach (var duplicate in latest.DuplicateFiles)
                data.DuplicateFiles.Add(new DuplicateScan(duplicate, latest.StableKey, latest.FileName));

            if (latest.IsScorable)
            {
                data.Clients.Add(latest);
            }
            else
            {
                data.SkippedAssets.Add(new SkippedAsset(
                    latest.FileName,
                    "Latest valid export has no Pass, Partial, or Fail findings; unavailable and not-assessed results are excluded from score coverage."));
            }
        }

        return data;
    }

    private static ClientSummary ParseClientSummary(
        string file,
        string json,
        int staleDays,
        DateTimeOffset now)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Findings export root must be an object.");

        var timestamp = RequiredString(root, "timestamp");
        var scanTime = ParseTimestamp(timestamp)
            ?? throw new InvalidDataException("Findings export timestamp is missing or invalid.");
        if (!root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Findings export must contain a findings array.");

        var client = OptionalString(root, "client");
        var target = OptionalString(root, "target");
        var host = target;
        var osCaption = "";
        if (root.TryGetProperty("environment", out var environment) && environment.ValueKind == JsonValueKind.Object)
        {
            host = FirstNonEmpty(OptionalString(environment, "computer_name"), target);
            osCaption = FirstNonEmpty(OptionalString(environment, "os_caption"), OptionalString(environment, "os"));
        }
        if (string.IsNullOrWhiteSpace(host))
            throw new InvalidDataException("Findings export has no target or environment.computer_name asset identity.");

        var summary = new ClientSummary
        {
            FileName = Path.GetFileName(file),
            Timestamp = timestamp,
            ScanTime = scanTime,
            Client = client,
            Host = host,
            OS = osCaption,
            IsStale = (now - scanTime).TotalDays > staleDays
        };

        foreach (var finding in findings.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object)
                continue;

            var status = OptionalString(finding, "status");
            var severity = OptionalString(finding, "severity");
            if (IsScorableStatus(status))
                summary.IsScorable = true;
            if (status.Equals("fail", StringComparison.OrdinalIgnoreCase))
            {
                summary.FailCount++;
                if (severity.Equals("critical", StringComparison.OrdinalIgnoreCase))
                    summary.CriticalCount++;
            }

            var remediationStatus = "";
            var dueDate = OptionalDate(finding, "remediation_due_date");
            if (finding.TryGetProperty("remediation", out var remediation) && remediation.ValueKind == JsonValueKind.Object)
            {
                remediationStatus = OptionalString(remediation, "status");
                dueDate ??= OptionalDate(remediation, "due");
            }

            if (status.Equals("fail", StringComparison.OrdinalIgnoreCase) && !IsClosedRemediation(remediationStatus) &&
                !IsExceptionDisposition(remediationStatus))
            {
                summary.Remediations.Add(new RemediationItem(dueDate));
            }

            if (status.Equals("fail", StringComparison.OrdinalIgnoreCase) &&
                (severity.Equals("high", StringComparison.OrdinalIgnoreCase) || severity.Equals("critical", StringComparison.OrdinalIgnoreCase)))
            {
                var age = OptionalInt(finding, "exposure_days") ?? OptionalInt(finding, "age_days");
                if (age is null && OptionalDateTimeOffset(finding, "first_seen") is { } firstSeen)
                    age = Math.Max(0, (int)Math.Floor((now - firstSeen).TotalDays));
                summary.Exposures.Add(new ExposureItem(severity, age));
            }
        }

        if (summary.IsScorable)
        {
            if (!root.TryGetProperty("score", out var score) || score.ValueKind != JsonValueKind.Object ||
                OptionalInt(score, "overall") is not { } overall || overall is < 0 or > 100)
                throw new InvalidDataException("Scorable findings export must contain score.overall from 0 through 100.");

            summary.OverallScore = overall;
            summary.Grade = RequiredString(score, "grade");
            summary.RansomwareScore = OptionalInt(score, "ransomware_readiness") ?? 0;
            if (score.TryGetProperty("ransomware", out var ransomware) && ransomware.ValueKind == JsonValueKind.Object)
                summary.RansomwareScore = OptionalInt(ransomware, "score") ?? summary.RansomwareScore;
        }

        ParseContinuousMetrics(root, summary);
        ParseExceptions(root, summary, now);
        summary.StableKey = BuildStableKey(summary);

        var htmlSibling = Path.ChangeExtension(file, ".html")
            .Replace("_findings.html", ".html", StringComparison.OrdinalIgnoreCase);
        if (File.Exists(htmlSibling))
            summary.ReportPath = Path.GetFileName(htmlSibling);

        return summary;
    }

    private static void ParseContinuousMetrics(JsonElement root, ClientSummary summary)
    {
        if (!root.TryGetProperty("continuous", out var continuous) || continuous.ValueKind != JsonValueKind.Object)
            return;

        if (continuous.TryGetProperty("delta", out var delta) && delta.ValueKind == JsonValueKind.Object)
        {
            summary.NewCriticals = OptionalInt(delta, "new_criticals") ?? 0;
            summary.ResolvedCriticals = OptionalInt(delta, "resolved_criticals") ?? 0;
            summary.HasCriticalDelta = true;
        }

        if (!continuous.TryGetProperty("exposure", out var exposure) || exposure.ValueKind != JsonValueKind.Object)
            return;

        foreach (var item in exposure.EnumerateObject())
        {
            if (item.Value.ValueKind != JsonValueKind.Object)
                continue;
            var severity = OptionalString(item.Value, "severity");
            if (!severity.Equals("high", StringComparison.OrdinalIgnoreCase) &&
                !severity.Equals("critical", StringComparison.OrdinalIgnoreCase))
                continue;
            summary.Exposures.Add(new ExposureItem(severity, OptionalInt(item.Value, "days")));
        }
    }

    private static void ParseExceptions(JsonElement root, ClientSummary summary, DateTimeOffset now)
    {
        if (!root.TryGetProperty("exceptions", out var exceptions) || exceptions.ValueKind != JsonValueKind.Array)
            return;

        foreach (var item in exceptions.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;
            var state = FirstNonEmpty(OptionalString(item, "disposition"), OptionalString(item, "status"));
            if (state.Equals("revoked", StringComparison.OrdinalIgnoreCase) ||
                state.Equals("rejected", StringComparison.OrdinalIgnoreCase))
                continue;

            var expiration = OptionalDate(item, "expiration") ?? OptionalDate(item, "expiration_date");
            var expired = state.Equals("expired", StringComparison.OrdinalIgnoreCase) ||
                (expiration is { } date && date < DateOnly.FromDateTime(now.UtcDateTime));
            if (expired)
                summary.ExpiredExceptions++;
            else
                summary.ActiveExceptions++;
        }
    }

    private static DashboardMetrics BuildMetrics(DashboardData data)
    {
        var scores = data.Clients.Select(c => c.OverallScore).Order().ToArray();
        var median = scores.Length switch
        {
            0 => (double?)null,
            _ when scores.Length % 2 == 1 => scores[scores.Length / 2],
            _ => (scores[scores.Length / 2 - 1] + scores[scores.Length / 2]) / 2.0
        };
        var validAssets = data.Clients.Count + data.SkippedAssets.Count;
        var discoveredAssets = validAssets + data.FailedFiles.Count;
        var remediations = data.Clients.SelectMany(c => c.Remediations).ToArray();
        var today = data.GeneratedAtDate;

        var metrics = new DashboardMetrics
        {
            AssetsDiscovered = discoveredAssets,
            AssetsValid = validAssets,
            AssetsScanned = data.Clients.Count,
            AssetsSkipped = data.SkippedAssets.Count,
            AssetsFailed = data.FailedFiles.Count,
            CoverageDenominator = discoveredAssets,
            CoveragePercentage = discoveredAssets == 0 ? null : Math.Round((double)data.Clients.Count / discoveredAssets * 100, 1),
            FreshAssets = data.Clients.Count(c => !c.IsStale),
            StaleAssets = data.Clients.Count(c => c.IsStale),
            FreshnessDenominator = data.Clients.Count,
            AverageScore = scores.Length == 0 ? null : Math.Round(scores.Average(), 1),
            MedianScore = median,
            ScorePopulation = scores.Length,
            OpenCriticals = data.Clients.Sum(c => c.CriticalCount),
            NewCriticals = data.Clients.Sum(c => c.NewCriticals),
            ResolvedCriticals = data.Clients.Sum(c => c.ResolvedCriticals),
            CriticalChangeDenominator = data.Clients.Count(c => c.HasCriticalDelta),
            ActiveExceptions = data.Clients.Sum(c => c.ActiveExceptions),
            ExpiredExceptions = data.Clients.Sum(c => c.ExpiredExceptions),
            RemediationDenominator = remediations.Length
        };
        metrics.ExceptionDenominator = metrics.ActiveExceptions + metrics.ExpiredExceptions;

        var highAges = data.Clients.SelectMany(c => c.Exposures)
            .Where(e => e.Severity.Equals("high", StringComparison.OrdinalIgnoreCase) && e.AgeDays.HasValue)
            .Select(e => e.AgeDays!.Value).ToArray();
        var criticalAges = data.Clients.SelectMany(c => c.Exposures)
            .Where(e => e.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase) && e.AgeDays.HasValue)
            .Select(e => e.AgeDays!.Value).ToArray();
        metrics.OldestHighAgeDays = highAges.Length == 0 ? null : highAges.Max();
        metrics.OldestCriticalAgeDays = criticalAges.Length == 0 ? null : criticalAges.Max();
        metrics.ExposureAgeDenominator = highAges.Length + criticalAges.Length;

        foreach (var item in remediations)
        {
            if (item.DueDate is null)
            {
                metrics.RemediationNoDueDate++;
                continue;
            }

            var overdue = today.DayNumber - item.DueDate.Value.DayNumber;
            if (overdue <= 0) metrics.RemediationNotDue++;
            else if (overdue <= 30) metrics.RemediationOverdue1To30++;
            else if (overdue <= 60) metrics.RemediationOverdue31To60++;
            else if (overdue <= 90) metrics.RemediationOverdue61To90++;
            else metrics.RemediationOverdue91Plus++;
        }

        return metrics;
    }

    private static object ToJsonRow(ClientSummary client) => new
    {
        client = client.Client,
        host = client.Host,
        os = client.OS,
        score = client.OverallScore,
        grade = client.Grade,
        ransomware = client.RansomwareScore,
        critical_fails = client.CriticalCount,
        total_fails = client.FailCount,
        stale = client.IsStale,
        scan_date = client.ScanTime.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        file = client.FileName,
        trend = client.Trend.Select(t => new { timestamp = t.Timestamp, score = t.Score }).ToArray(),
        duplicate_files = client.DuplicateFiles
    };

    private static string BuildHtml(DashboardData data, int staleDays, DateTimeOffset now)
    {
        var clients = data.Clients;
        var metrics = BuildMetrics(data);
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"<title>{Esc(UiText.DashboardDocumentTitle)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("""
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 32px; }
            h1 { color: #cba6f7; margin-bottom: 8px; } h2 { margin: 24px 0 10px; font-size: 18px; }
            .subtitle { color: #a6adc8; font-size: 14px; margin-bottom: 24px; }
            .summary-bar { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
            .summary-stat { background: #313244; border-radius: 8px; padding: 16px 20px; min-width: 150px; }
            .summary-stat .value { font-size: 28px; font-weight: 700; }
            .summary-stat .label { font-size: 11px; color: #a6adc8; text-transform: uppercase; letter-spacing: 1px; }
            .summary-stat .denominator { font-size: 11px; color: #a6adc8; margin-top: 4px; }
            table { width: 100%; border-collapse: collapse; background: #313244; border-radius: 8px; overflow: hidden; }
            caption { text-align: left; color: #a6adc8; font-size: 12px; padding: 0 0 8px; font-weight: 600; }
            th { background: #45475a; color: #cba6f7; text-align: left; padding: 10px 14px; font-size: 13px; text-transform: uppercase; }
            td { padding: 10px 14px; border-top: 1px solid #45475a; font-size: 14px; vertical-align: middle; }
            tr:hover { background: #3b3d50; }
            .grade-a { color: #a6e3a1; } .grade-b { color: #94e2d5; } .grade-c { color: #f9e2af; }
            .grade-d { color: #fab387; } .grade-f { color: #f38ba8; }
            .stale { color: #f38ba8; font-weight: 600; }
            .trend { width: 96px; height: 24px; overflow: visible; margin-right: 6px; vertical-align: middle; }
            .trend-line { fill: none; stroke: #89b4fa; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
            .trend-data { color: #a6adc8; font-size: 12px; white-space: nowrap; }
            .empty-state { background: #313244; border: 1px solid #45475a; border-radius: 8px; padding: 28px; margin-bottom: 24px; }
            .empty-state h2 { color: #cdd6f4; font-size: 18px; margin: 0 0 6px; }
            .empty-state p, .definition { color: #a6adc8; font-size: 12px; }
            .footer { text-align: center; padding: 24px; color: #7f849c; font-size: 12px; margin-top: 32px; }
            a { color: #89b4fa; text-decoration: none; } a:hover { text-decoration: underline; }
            @media (max-width: 768px) { body { padding: 12px; } .summary-bar { flex-direction: column; } table { display: block; overflow-x: auto; } }
            """);
        sb.AppendLine("</style></head><body>");

        sb.AppendLine($"<h1>{Esc(UiText.DashboardTitle)}</h1>");
        sb.AppendLine($"<p class=\"subtitle\">{Esc(UiText.Format(
            nameof(UiText.DashboardSubtitleFormat),
            now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
            staleDays,
            data.DuplicateFiles.Count))}</p>");
        sb.AppendLine("<div class=\"summary-bar\">");
        AppendStat(sb, $"{metrics.AssetsScanned}/{metrics.CoverageDenominator}", UiText.DashboardScanCoverage, metrics.CoveragePercentage is null ? "denominator n=0" : $"{D(metrics.CoveragePercentage)}%; denominator n={metrics.CoverageDenominator}");
        AppendStat(sb, D(metrics.AverageScore), UiText.DashboardAverageScore, $"n={metrics.ScorePopulation}; median {D(metrics.MedianScore)}");
        AppendStat(sb, metrics.OpenCriticals.ToString(CultureInfo.InvariantCulture), UiText.DashboardOpenCriticals, $"new {metrics.NewCriticals}; resolved {metrics.ResolvedCriticals}; delta n={metrics.CriticalChangeDenominator}");
        AppendStat(sb, metrics.StaleAssets.ToString(CultureInfo.InvariantCulture), UiText.DashboardStaleAssets, $"{metrics.FreshAssets} fresh / n={metrics.FreshnessDenominator}");
        AppendStat(sb, metrics.ActiveExceptions.ToString(CultureInfo.InvariantCulture), UiText.DashboardActiveExceptions, $"{metrics.ExpiredExceptions} expired / n={metrics.ExceptionDenominator}");
        AppendStat(sb, metrics.RemediationDenominator.ToString(CultureInfo.InvariantCulture), UiText.DashboardOpenRemediations, $"aging denominator n={metrics.RemediationDenominator}");
        sb.AppendLine("</div>");
        sb.AppendLine($"<p class=\"definition\">{Esc(UiText.Format(
            nameof(UiText.DashboardAssetDefinitionFormat),
            metrics.AssetsDiscovered,
            metrics.AssetsValid,
            metrics.AssetsScanned,
            metrics.AssetsSkipped,
            metrics.AssetsFailed))}</p>");

        sb.AppendLine($"<h2>{Esc(UiText.DashboardOperationalAging)}</h2>");
        sb.AppendLine($"<table><thead><tr><th scope=\"col\">{Esc(UiText.DashboardOldestHigh)}</th><th scope=\"col\">{Esc(UiText.DashboardOldestCritical)}</th><th scope=\"col\">{Esc(UiText.DashboardNotDue)}</th><th scope=\"col\">{Esc(UiText.DashboardOverdue1To30)}</th><th scope=\"col\">{Esc(UiText.DashboardOverdue31To60)}</th><th scope=\"col\">{Esc(UiText.DashboardOverdue61To90)}</th><th scope=\"col\">{Esc(UiText.DashboardOverdue91Plus)}</th><th scope=\"col\">{Esc(UiText.DashboardNoDueDate)}</th></tr></thead><tbody><tr>");
        sb.AppendLine($"<td>{Days(metrics.OldestHighAgeDays)}</td><td>{Days(metrics.OldestCriticalAgeDays)}</td><td>{metrics.RemediationNotDue}</td><td>{metrics.RemediationOverdue1To30}</td><td>{metrics.RemediationOverdue31To60}</td><td>{metrics.RemediationOverdue61To90}</td><td>{metrics.RemediationOverdue91Plus}</td><td>{metrics.RemediationNoDueDate}</td></tr></tbody></table>");
        sb.AppendLine($"<p class=\"definition\">{Esc(UiText.Format(
            nameof(UiText.DashboardExposureDefinitionFormat),
            metrics.ExposureAgeDenominator,
            metrics.RemediationDenominator))}</p>");

        if (clients.Count == 0)
        {
            sb.AppendLine("<section class=\"empty-state\" aria-live=\"polite\">");
            sb.AppendLine($"<h2>{Esc(UiText.DashboardEmpty)}</h2>");
            sb.AppendLine($"<p>{Esc(UiText.DashboardEmptyDetail)}</p>");
            sb.AppendLine("</section>");
        }
        else
        {
            sb.AppendLine($"<h2>{Esc(UiText.DashboardScannedAssets)}</h2><table>");
            sb.AppendLine($"<caption>{Esc(UiText.DashboardScannedAssetsCaption)}</caption>");
            sb.AppendLine($"<thead><tr><th scope=\"col\">{Esc(UiText.TableClient)}</th><th scope=\"col\">{Esc(UiText.TableHost)}</th><th scope=\"col\">{Esc(UiText.TableScore)}</th><th scope=\"col\">{Esc(UiText.TableGrade)}</th><th scope=\"col\">{Esc(UiText.TableTrend)}</th><th scope=\"col\">{Esc(UiText.Ransomware)}</th><th scope=\"col\">{Esc(UiText.TableCritical)}</th><th scope=\"col\">{Esc(UiText.TableFails)}</th><th scope=\"col\">{Esc(UiText.TableScanDate)}</th><th scope=\"col\">{Esc(UiText.TableReport)}</th></tr></thead><tbody>");

            foreach (var c in SortDashboardRows(clients))
            {
                var staleFlag = c.IsStale ? $" <span class=\"stale\">[{Esc(UiText.DashboardStale)}]</span>" : "";
                var reportLink = c.ReportPath is not null
                    ? $"<a href=\"{Esc(Uri.EscapeDataString(c.ReportPath))}\" aria-label=\"{Esc(UiText.Format(nameof(UiText.DashboardOpenReportAriaFormat), c.Client, c.Host))}\">{Esc(UiText.DashboardOpenReport)}</a>"
                    : "";
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{Esc(c.Client)}</td><td>{Esc(c.Host)} <span style=\"font-size:11px;color:#a6adc8\">{Esc(c.OS)}</span></td>");
                sb.AppendLine($"<td>{c.OverallScore}%</td><td class=\"{GradeCssClass(c.Grade)}\" style=\"font-size:20px;font-weight:700\">{Esc(c.Grade)}</td>");
                sb.AppendLine($"<td>{BuildTrendSparkline(c.Trend)}</td><td>{c.RansomwareScore}%</td>");
                sb.AppendLine($"<td style=\"color:{(c.CriticalCount > 0 ? "#f38ba8" : "#a6e3a1")}\">{c.CriticalCount}</td><td>{c.FailCount}</td>");
                sb.AppendLine($"<td>{c.ScanTime.UtcDateTime:yyyy-MM-dd}{staleFlag}</td><td>{reportLink}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
        }

        AppendDiagnostics(sb, data);
        sb.AppendLine($"<div class=\"footer\">{Esc(UiText.Format(nameof(UiText.DashboardFooterFormat), VersionInfo.Version))}</div>");
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static void AppendDiagnostics(StringBuilder sb, DashboardData data)
    {
        if (data.DuplicateFiles.Count > 0)
        {
            sb.AppendLine($"<p style=\"color:#f9e2af;margin-top:16px;font-size:13px\">{Esc(UiText.Format(nameof(UiText.DashboardOlderDuplicatesFormat), data.DuplicateFiles.Count))}</p><ul>");
            foreach (var duplicate in data.DuplicateFiles.OrderBy(d => d.FileName, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"<li>{Esc(UiText.Format(nameof(UiText.DashboardLatestDuplicateFormat), duplicate.FileName, duplicate.StableKey, duplicate.LatestFileName))}</li>");
            sb.AppendLine("</ul>");
        }

        if (data.SkippedAssets.Count > 0)
        {
            sb.AppendLine($"<p style=\"color:#f9e2af;margin-top:16px;font-size:13px\">{Esc(UiText.Format(nameof(UiText.DashboardExcludedAssetsFormat), data.SkippedAssets.Count))}</p><ul>");
            foreach (var skipped in data.SkippedAssets.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"<li>{Esc(skipped.FileName)}: {Esc(skipped.Reason)}</li>");
            sb.AppendLine("</ul>");
        }

        if (data.FailedFiles.Count > 0)
        {
            sb.AppendLine($"<p style=\"color:#f38ba8;margin-top:16px;font-size:13px\">{Esc(UiText.Format(nameof(UiText.DashboardFailedFilesFormat), data.FailedFiles.Count))}</p><ul>");
            foreach (var failed in data.FailedFiles.OrderBy(s => s.FileName, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"<li>{Esc(failed.FileName)}: {Esc(failed.Reason)}</li>");
            sb.AppendLine("</ul>");
        }
    }

    private static void AppendStat(StringBuilder sb, string value, string label, string denominator) =>
        sb.AppendLine($"<div class=\"summary-stat\"><div class=\"value\">{Esc(value)}</div><div class=\"label\">{Esc(label)}</div><div class=\"denominator\">{Esc(denominator)}</div></div>");

    private static IEnumerable<ClientSummary> SortDashboardRows(IEnumerable<ClientSummary> clients) =>
        clients.OrderByDescending(c => c.CriticalCount)
            .ThenBy(c => c.OverallScore)
            .ThenBy(c => c.Client, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Host, StringComparer.OrdinalIgnoreCase);

    private static string BuildStableKey(ClientSummary client)
    {
        var clientKey = string.IsNullOrWhiteSpace(client.Client) ? "(unassigned-client)" : client.Client;
        return $"{NormalizeKey(clientKey)}|{NormalizeKey(client.Host)}";
    }

    private static string NormalizeKey(string value) => value.Trim().ToUpperInvariant();

    private static DateTimeOffset? ParseTimestamp(string timestamp) =>
        DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
            ? value
            : null;

    private static string FormatTrend(IReadOnlyList<TrendPoint> trend) =>
        string.Join("|", trend.Select(p => $"{p.Timestamp}:{p.Score}"));

    private static string BuildTrendSparkline(IReadOnlyList<TrendPoint> trend)
    {
        if (trend.Count == 0) return "";
        var title = Esc(FormatTrend(trend));
        if (trend.Count == 1)
            return $"<span class=\"trend-data\" title=\"{title}\">{trend[0].Score}%</span>";

        const double width = 96;
        const double height = 24;
        var points = trend.Select((point, index) =>
        {
            var x = index * width / Math.Max(1, trend.Count - 1);
            var y = height - Math.Clamp(point.Score, 0, 100) * height / 100;
            return FormattableString.Invariant($"{x:F1},{y:F1}");
        });
        var label = $"{trend.First().Score}% -> {trend.Last().Score}%";
        return $"<svg class=\"trend\" viewBox=\"0 0 {width:0} {height:0}\" role=\"img\" aria-label=\"{title}\"><polyline class=\"trend-line\" points=\"{string.Join(' ', points)}\" /></svg><span class=\"trend-data\">{Esc(label)}</span>";
    }

    private static bool IsScorableStatus(string status) =>
        status.Equals("pass", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("partial", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("fail", StringComparison.OrdinalIgnoreCase);

    private static bool IsClosedRemediation(string status) =>
        status.Equals("closed", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("complete", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("completed", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("resolved", StringComparison.OrdinalIgnoreCase);

    private static bool IsExceptionDisposition(string status) =>
        status.Equals("accepted risk", StringComparison.OrdinalIgnoreCase) ||
        status.Equals("deferred", StringComparison.OrdinalIgnoreCase);

    private static string RequiredString(JsonElement element, string name)
    {
        var value = OptionalString(element, name);
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"Findings export property '{name}' is required.");
        return value;
    }

    private static string OptionalString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";

    private static int? OptionalInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)) return number;
        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)) return number;
        return null;
    }

    private static DateOnly? OptionalDate(JsonElement element, string name)
    {
        var value = OptionalString(element, name);
        return DateOnly.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;
    }

    private static DateTimeOffset? OptionalDateTimeOffset(JsonElement element, string name)
    {
        var value = OptionalString(element, name);
        return ParseTimestamp(value);
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";

    private static string Esc(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private static string CsvEsc(string? value) => CsvExporter.Escape(value);

    private static void AppendCsvRow(StringBuilder sb, IEnumerable<string> fields) =>
        sb.AppendLine(string.Join(",", fields.Select(CsvEsc)));

    private static string I(int value) => value.ToString(CultureInfo.InvariantCulture);
    private static string I(int? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "";
    private static string D(double? value) => value?.ToString("0.#", CultureInfo.InvariantCulture) ?? "N/A";
    private static string Days(int? value) => value is null ? "N/A" : $"{value} days";

    private static string GradeCssClass(string? grade)
    {
        var trimmed = grade?.Trim();
        if (trimmed is { Length: 1 } && trimmed[0] is 'A' or 'a' or 'B' or 'b' or 'C' or 'c' or 'D' or 'd' or 'E' or 'e' or 'F' or 'f')
            return $"grade-{char.ToLowerInvariant(trimmed[0])}";
        return "grade-unknown";
    }

    private sealed class DashboardData
    {
        public int InputFilesDiscovered { get; set; }
        public DateOnly GeneratedAtDate { get; init; }
        public List<ClientSummary> ValidScans { get; } = [];
        public List<ClientSummary> Clients { get; } = [];
        public List<FailedFile> FailedFiles { get; } = [];
        public List<SkippedAsset> SkippedAssets { get; } = [];
        public List<DuplicateScan> DuplicateFiles { get; } = [];
    }

    private sealed record FailedFile(string FileName, string Reason);
    private sealed record SkippedAsset(string FileName, string Reason);
    private sealed record DuplicateScan(string FileName, string StableKey, string LatestFileName);
    private sealed record TrendPoint(string Timestamp, int Score);
    private sealed record RemediationItem(DateOnly? DueDate);
    private sealed record ExposureItem(string Severity, int? AgeDays);

    private sealed class ClientSummary
    {
        public string FileName { get; set; } = "";
        public string StableKey { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public DateTimeOffset ScanTime { get; set; }
        public string Client { get; set; } = "";
        public string Host { get; set; } = "";
        public string OS { get; set; } = "";
        public bool IsScorable { get; set; }
        public int OverallScore { get; set; }
        public string Grade { get; set; } = "";
        public int RansomwareScore { get; set; }
        public int FailCount { get; set; }
        public int CriticalCount { get; set; }
        public bool IsStale { get; set; }
        public string? ReportPath { get; set; }
        public int NewCriticals { get; set; }
        public int ResolvedCriticals { get; set; }
        public bool HasCriticalDelta { get; set; }
        public int ActiveExceptions { get; set; }
        public int ExpiredExceptions { get; set; }
        public List<RemediationItem> Remediations { get; } = [];
        public List<ExposureItem> Exposures { get; } = [];
        public List<TrendPoint> Trend { get; set; } = [];
        public List<string> DuplicateFiles { get; set; } = [];
    }

    private sealed class DashboardMetrics
    {
        public int AssetsDiscovered { get; set; }
        public int AssetsValid { get; set; }
        public int AssetsScanned { get; set; }
        public int AssetsSkipped { get; set; }
        public int AssetsFailed { get; set; }
        public int CoverageDenominator { get; set; }
        public double? CoveragePercentage { get; set; }
        public int FreshAssets { get; set; }
        public int StaleAssets { get; set; }
        public int UnknownFreshnessAssets { get; set; }
        public int FreshnessDenominator { get; set; }
        public double? AverageScore { get; set; }
        public double? MedianScore { get; set; }
        public int ScorePopulation { get; set; }
        public int OpenCriticals { get; set; }
        public int NewCriticals { get; set; }
        public int ResolvedCriticals { get; set; }
        public int CriticalChangeDenominator { get; set; }
        public int? OldestHighAgeDays { get; set; }
        public int? OldestCriticalAgeDays { get; set; }
        public int ExposureAgeDenominator { get; set; }
        public int ActiveExceptions { get; set; }
        public int ExpiredExceptions { get; set; }
        public int ExceptionDenominator { get; set; }
        public int RemediationDenominator { get; set; }
        public int RemediationNotDue { get; set; }
        public int RemediationOverdue1To30 { get; set; }
        public int RemediationOverdue31To60 { get; set; }
        public int RemediationOverdue61To90 { get; set; }
        public int RemediationOverdue91Plus { get; set; }
        public int RemediationNoDueDate { get; set; }
    }
}

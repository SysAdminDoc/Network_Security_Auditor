using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class ComplianceSummaryExporter
{
    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        int ransomwareScore,
        string ransomwareGrade,
        int domainMaturityScore,
        string domainMaturityGrade)
    {
        var checkList = checks.ToList();
        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);

        var categoryScores = checkList
            .GroupBy(c => c.Category)
            .ToDictionary(
                g => g.Key,
                g =>
                {
                    var assessed = g.Where(c => c.Status is not (CheckStatus.NA or CheckStatus.NotAssessed)).ToList();
                    var passing = assessed.Count(c => c.Status is CheckStatus.Pass or CheckStatus.Partial);
                    return new { Total = assessed.Count, Passing = passing, Pct = assessed.Count > 0 ? Math.Round((double)passing / assessed.Count * 100, 1) : 0.0 };
                });

        var frameworkScores = new Dictionary<string, object>();
        foreach (var (name, sel) in FrameworkDefinitions.All)
        {
            var mapped = FrameworkMappings.All.Where(kv => sel(kv.Value) is not null).Select(kv => kv.Key).ToList();
            int total = 0, passing = 0;
            foreach (var cid in mapped)
            {
                if (!statusLookup.TryGetValue(cid, out var st) || st is CheckStatus.NA or CheckStatus.NotAssessed) continue;
                total++;
                if (st is CheckStatus.Pass or CheckStatus.Partial) passing++;
            }
            frameworkScores[name] = new { Total = total, Passing = passing, Pct = total > 0 ? Math.Round((double)passing / total * 100, 1) : 0.0 };
        }

        var criticalFails = checkList
            .Where(c => c.Status == CheckStatus.Fail && c.Severity == Severity.Critical)
            .Select(c => new { c.Id, c.Label, c.Category })
            .ToArray();

        var summary = new
        {
            schema_version = "2.1",
            tool = "NetworkSecurityAuditor",
            tool_version = VersionInfo.Version,
            timestamp = DateTime.UtcNow.ToString("o"),
            host = env.ComputerName,
            os = env.OSCaption,
            domain = env.DomainName,
            score = new { overall = overallScore, grade, ransomware = ransomwareScore, ransomware_grade = ransomwareGrade, domain_maturity = domainMaturityScore, domain_maturity_grade = domainMaturityGrade },
            counts = new
            {
                total = checkList.Count,
                pass = checkList.Count(c => c.Status == CheckStatus.Pass),
                partial = checkList.Count(c => c.Status == CheckStatus.Partial),
                fail = checkList.Count(c => c.Status == CheckStatus.Fail),
                na = checkList.Count(c => c.Status is CheckStatus.NA or CheckStatus.NotAssessed),
                critical_failures = criticalFails.Length
            },
            category_scores = categoryScores,
            framework_scores = frameworkScores,
            critical_failures = criticalFails
        };

        return JsonSerializer.Serialize(summary, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }
}

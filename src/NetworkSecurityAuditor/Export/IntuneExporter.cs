using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class IntuneExporter
{
    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        int ransomwareScore,
        string ransomwareGrade)
    {
        var checkList = checks.ToList();
        var criticalFails = checkList
            .Where(c => c.Status == CheckStatus.Fail && c.Severity == Severity.Critical)
            .Select(c => c.Id)
            .ToArray();

        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);
        var complianceFlags = new Dictionary<string, bool>();
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
            complianceFlags[name] = total > 0 && (double)passing / total * 100 >= 60;
        }

        var output = new
        {
            schema_version = "1.0",
            tool = "NetworkSecurityAuditor",
            tool_version = VersionInfo.Version,
            timestamp = DateTime.UtcNow.ToString("o"),
            host = env.ComputerName,
            os = env.OSCaption,
            SecurityAuditGrade = grade,
            SecurityAuditScore = overallScore,
            RansomwareReadinessScore = ransomwareScore,
            RansomwareReadinessGrade = ransomwareGrade,
            CriticalFailures = criticalFails,
            CriticalFailureCount = criticalFails.Length,
            ComplianceFlags = complianceFlags,
            TotalChecks = checkList.Count,
            PassCount = checkList.Count(c => c.Status == CheckStatus.Pass),
            FailCount = checkList.Count(c => c.Status == CheckStatus.Fail),
            PartialCount = checkList.Count(c => c.Status == CheckStatus.Partial)
        };

        return JsonSerializer.Serialize(output, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }
}

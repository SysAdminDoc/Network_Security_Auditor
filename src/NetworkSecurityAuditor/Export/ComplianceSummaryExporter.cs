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
        string domainMaturityGrade,
        IReadOnlyList<RiskWaiver>? waiverHistory = null,
        DateTimeOffset? generatedAt = null)
    {
        var checkList = checks.ToList();
        var now = (generatedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);

        var categoryScores = checkList
            .GroupBy(c => c.Category)
            .ToDictionary(
                g => g.Key,
                g =>
                {
                    var assessed = g.Where(c => c.Status is not (CheckStatus.NA or CheckStatus.NotAssessed)).ToList();
                    var met = assessed.Count(c => c.Status == CheckStatus.Pass);
                    var partial = assessed.Count(c => c.Status == CheckStatus.Partial);
                    var failing = assessed.Count(c => c.Status == CheckStatus.Fail);
                    return new
                    {
                        Total = assessed.Count,
                        Denominator = assessed.Count,
                        Met = met,
                        Partial = partial,
                        Failing = failing,
                        Pct = assessed.Count > 0 ? Math.Round((double)met / assessed.Count * 100, 1) : 0.0
                    };
                });

        var frameworkScores = new Dictionary<string, object>();
        foreach (var (name, sel) in FrameworkDefinitions.All)
        {
            var mapped = FrameworkMappings.All.Where(kv => sel(kv.Value) is not null).Select(kv => kv.Key).ToList();
            int assessed = 0, met = 0, partial = 0, failing = 0, notAssessed = 0;
            foreach (var cid in mapped)
            {
                if (!statusLookup.TryGetValue(cid, out var st) || st is CheckStatus.NA or CheckStatus.NotAssessed)
                {
                    notAssessed++;
                    continue;
                }

                assessed++;
                if (st == CheckStatus.Pass) met++;
                else if (st == CheckStatus.Partial) partial++;
                else if (st == CheckStatus.Fail) failing++;
            }
            frameworkScores[name] = new
            {
                Mapped = mapped.Count,
                Total = assessed,
                Denominator = assessed,
                Met = met,
                Partial = partial,
                Failing = failing,
                NotAssessed = notAssessed,
                Pct = assessed > 0 ? Math.Round((double)met / assessed * 100, 1) : 0.0
            };
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
            timestamp = now.ToString("o"),
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
            critical_failures = criticalFails,
            executive_kpis = BuildExecutiveKpis(checkList, overallScore, waiverHistory, now)
        };

        return JsonSerializer.Serialize(summary, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never
        });
    }

    private static object BuildExecutiveKpis(
        IReadOnlyList<CheckItemViewModel> checks,
        int overallScore,
        IReadOnlyList<RiskWaiver>? waiverHistory,
        DateTimeOffset now)
    {
        var scorable = checks.Count(check => check.Status is CheckStatus.Pass or CheckStatus.Partial or CheckStatus.Fail);
        var wasScanned = scorable > 0;
        var latestWaivers = waiverHistory?
            .GroupBy(waiver => waiver.CheckId, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(waiver => waiver.LastActivityDate).Last())
            .ToArray() ?? [];
        var activeWaiverIds = latestWaivers
            .Where(waiver => waiver.EffectiveStatus == WaiverDispositionState.Approved)
            .Select(waiver => waiver.CheckId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var activeExceptions = latestWaivers.Count(waiver => waiver.EffectiveStatus == WaiverDispositionState.Approved);
        var expiredExceptions = latestWaivers.Count(waiver => waiver.EffectiveStatus == WaiverDispositionState.Expired);

        var openRemediations = checks
            .Where(check => check.Status == CheckStatus.Fail && !activeWaiverIds.Contains(check.Id))
            .ToArray();
        var notDue = 0;
        var overdue1To30 = 0;
        var overdue31To60 = 0;
        var overdue61To90 = 0;
        var overdue91Plus = 0;
        var noDueDate = 0;
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        foreach (var check in openRemediations)
        {
            if (check.RemediationDueDate is null)
            {
                noDueDate++;
                continue;
            }

            var due = DateOnly.FromDateTime(check.RemediationDueDate.Value);
            var overdue = today.DayNumber - due.DayNumber;
            if (overdue <= 0) notDue++;
            else if (overdue <= 30) overdue1To30++;
            else if (overdue <= 60) overdue31To60++;
            else if (overdue <= 90) overdue61To90++;
            else overdue91Plus++;
        }

        return new
        {
            assets_discovered = 1,
            assets_valid = 1,
            assets_scanned = wasScanned ? 1 : 0,
            assets_skipped = wasScanned ? 0 : 1,
            assets_failed = 0,
            coverage = new
            {
                numerator = wasScanned ? 1 : 0,
                denominator = 1,
                percentage = wasScanned ? 100.0 : 0.0
            },
            freshness = new { fresh = wasScanned ? 1 : 0, stale = 0, unknown = 0, denominator = wasScanned ? 1 : 0 },
            scores = new
            {
                average = wasScanned ? overallScore : (int?)null,
                median = wasScanned ? overallScore : (int?)null,
                population = wasScanned ? 1 : 0,
                population_definition = "this asset when at least one check is Pass, Partial, or Fail"
            },
            critical_findings = new
            {
                open = checks.Count(check => check.Status == CheckStatus.Fail && check.Severity == Severity.Critical),
                open_denominator = wasScanned ? 1 : 0,
                @new = 0,
                resolved = 0,
                change_denominator = 0,
                oldest_high_age_days = (int?)null,
                oldest_critical_age_days = (int?)null,
                age_denominator = 0
            },
            exceptions = new
            {
                active = activeExceptions,
                expired = expiredExceptions,
                denominator = activeExceptions + expiredExceptions
            },
            remediation_aging = new
            {
                denominator = openRemediations.Length,
                not_due = notDue,
                overdue_1_to_30_days = overdue1To30,
                overdue_31_to_60_days = overdue31To60,
                overdue_61_to_90_days = overdue61To90,
                overdue_91_plus_days = overdue91Plus,
                no_due_date = noDueDate
            }
        };
    }
}

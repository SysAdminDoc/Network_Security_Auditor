using System.Collections.ObjectModel;
using System.Text.Json;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class StatusModelTests
{
    private static readonly CheckStatus[] ScoredStatuses = [CheckStatus.Pass, CheckStatus.Partial, CheckStatus.Fail];

    [Fact]
    public void Only_Pass_Partial_And_Fail_Are_Scored()
    {
        foreach (var status in Enum.GetValues<CheckStatus>())
            Assert.Equal(ScoredStatuses.Contains(status), status.IsScored());
    }

    [Fact]
    public void Evidence_Modes_Match_The_Questionnaire_Set()
    {
        foreach (var (id, meta) in CheckCatalog.All)
        {
            var questionnaire = CheckCatalog.QuestionnaireIds.Contains(id);
            switch (meta.EvidenceMode)
            {
                case EvidenceMode.Checklist or EvidenceMode.InterviewRequired:
                    Assert.True(questionnaire, $"{id} is {meta.EvidenceMode} but the scan would score it.");
                    break;
                case EvidenceMode.Automated or EvidenceMode.Heuristic:
                    Assert.False(questionnaire, $"{id} is {meta.EvidenceMode} but is treated as a questionnaire.");
                    break;
            }
        }

        foreach (var id in CheckCatalog.QuestionnaireIds)
            Assert.True(CheckCatalog.All.ContainsKey(id), $"{id} is in QuestionnaireIds but not in the catalog.");
    }

    [Fact]
    public void Ps1_Evidence_Modes_Match_The_Catalog()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "NetworkSecurityAudit.ps1"));
        var ps1Modes = System.Text.RegularExpressions.Regex
            .Matches(script, @"^\s*'([A-Z]{2}\d{2})' = @\{ EvidenceMode='(\w+)'", System.Text.RegularExpressions.RegexOptions.Multiline)
            .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);

        Assert.Equal(CheckCatalog.All.Count, ps1Modes.Count);
        foreach (var (id, meta) in CheckCatalog.All)
            Assert.True(ps1Modes.TryGetValue(id, out var mode) && mode == meta.EvidenceMode.ToString(),
                $"{id}: catalog {meta.EvidenceMode}, PS1 {ps1Modes.GetValueOrDefault(id) ?? "missing"}.");
    }

    [Fact]
    public void Questionnaire_Checks_Never_Set_A_Scored_Status_And_Every_Other_Check_Can()
    {
        var checksDir = Path.Combine(FindRepoRoot(), "src", "NetworkSecurityAuditor", "Checks");
        foreach (var id in CheckCatalog.All.Keys)
        {
            var files = Directory.GetFiles(checksDir, $"{id}_*.cs", SearchOption.AllDirectories);
            Assert.True(files.Length == 1, $"Expected one source file for {id}, found {files.Length}.");
            var source = File.ReadAllText(files[0]);
            var setsScoredStatus = ScoredStatuses.Any(status => source.Contains($"CheckStatus.{status}", StringComparison.Ordinal));

            if (CheckCatalog.QuestionnaireIds.Contains(id))
                Assert.False(setsScoredStatus, $"{id} is a questionnaire check but its source sets a scored status.");
            else
                Assert.True(setsScoredStatus, $"{id} never sets Pass, Partial or Fail; add it to QuestionnaireIds.");
        }
    }

    [Fact]
    public async Task Questionnaire_Checks_Return_NotAssessed_On_The_Live_Host()
    {
        var checks = CheckRegistry.GetAllChecks();
        foreach (var id in CheckCatalog.QuestionnaireIds)
        {
            var result = await checks[id].ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
            Assert.True(result.Status == CheckStatus.NotAssessed, $"{id} returned {result.Status}.");
        }
    }

    [Fact]
    public void Thrown_Checks_Are_Errors_And_Missing_Checks_Stay_NA()
    {
        Assert.Equal(CheckStatus.Error, CheckResult.FromError("EP01", new InvalidOperationException("boom")).Status);
        Assert.Equal(CheckStatus.NA, CheckResult.NotImplemented("EP01").Status);
    }

    [Theory]
    [InlineData("PS01", CheckStatus.Pass, CheckStatus.NotAssessed, CheckStatus.Pass)]
    [InlineData("PS01", CheckStatus.Fail, CheckStatus.NotAssessed, CheckStatus.Fail)]
    [InlineData("PS01", CheckStatus.NA, CheckStatus.NotAssessed, CheckStatus.NA)]
    [InlineData("PS01", CheckStatus.Error, CheckStatus.NotAssessed, CheckStatus.NotAssessed)]
    [InlineData("PS01", CheckStatus.Pass, CheckStatus.Error, CheckStatus.Error)]
    [InlineData("EP01", CheckStatus.Pass, CheckStatus.NotAssessed, CheckStatus.NotAssessed)]
    [InlineData("EP01", CheckStatus.Pass, CheckStatus.Fail, CheckStatus.Fail)]
    public void Rescan_Keeps_An_Operator_Answer_Only_On_Questionnaire_Checks(
        string id, CheckStatus current, CheckStatus scanned, CheckStatus expected)
    {
        Assert.Equal(expected, MainViewModel.MergeScanStatus(id, current, scanned));
    }

    [Fact]
    public void Errors_And_Unanswered_Checks_Do_Not_Move_Any_Score()
    {
        var baseline = CreateChecks(("EP01", CheckStatus.Pass), ("EP02", CheckStatus.Fail), ("BR01", CheckStatus.Partial));
        var withGaps = CreateChecks(("EP01", CheckStatus.Pass), ("EP02", CheckStatus.Fail), ("BR01", CheckStatus.Partial),
            ("EP03", CheckStatus.Error), ("IA05", CheckStatus.Error), ("PS01", CheckStatus.NotAssessed), ("BR03", CheckStatus.NotAssessed));

        Assert.Equal(RiskScoreEngine.Calculate(baseline), RiskScoreEngine.Calculate(withGaps));
        Assert.Equal(RansomwareReadinessEngine.Calculate(baseline), RansomwareReadinessEngine.Calculate(withGaps));
        Assert.Equal(SprsScoreEngine.Calculate(baseline), SprsScoreEngine.Calculate(withGaps));
    }

    [Fact]
    public void Coverage_Counts_Errors_Timeouts_And_Unanswered_Checks_Against_Applicable_Checks()
    {
        var checks = CreateChecks(("EP01", CheckStatus.Pass), ("EP02", CheckStatus.Fail), ("EP03", CheckStatus.Error),
            ("EP05", CheckStatus.Error), ("PS01", CheckStatus.NotAssessed), ("EP07", CheckStatus.NA));
        checks.Single(c => c.Id == "EP05").Evidence = "Timeout @ 2026-09-30 12:00 UTC";

        var coverage = CoverageSummary.From(checks);

        Assert.Equal(6, coverage.Total);
        Assert.Equal(5, coverage.Applicable);
        Assert.Equal(2, coverage.Scored);
        Assert.Equal(2, coverage.Errors);
        Assert.Equal(1, coverage.TimedOut);
        Assert.Equal(1, coverage.NotAssessed);
        Assert.Equal(40.0, coverage.Pct);
    }

    [Fact]
    public void Framework_Exit_Threshold_Counts_Only_Pass()
    {
        var mapped = FrameworkMappings.All.Keys.Where(CheckCatalog.All.ContainsKey).ToArray();

        Assert.False(App.HasFrameworkBelowThreshold(CreateChecks(mapped.Select(id => (id, CheckStatus.Pass)).ToArray()), 60));
        Assert.True(App.HasFrameworkBelowThreshold(CreateChecks(mapped.Select(id => (id, CheckStatus.Partial)).ToArray()), 60));

        // Errors and unanswered checks drop out of the denominator rather than counting as met or unmet.
        var mostlyUnscored = mapped.Select((id, i) => (id, i % 3 == 0 ? CheckStatus.Pass : i % 3 == 1 ? CheckStatus.Error : CheckStatus.NotAssessed)).ToArray();
        Assert.False(App.HasFrameworkBelowThreshold(CreateChecks(mostlyUnscored), 60));
    }

    [Fact]
    public void Html_Report_Lists_Errors_And_Timeouts_Under_Limitations()
    {
        var checks = CreateChecks(("EP01", CheckStatus.Pass), ("EP03", CheckStatus.Error), ("EP05", CheckStatus.Error), ("PS01", CheckStatus.NotAssessed));
        var ep03 = checks.Single(c => c.Id == "EP03");
        ep03.Findings = "Check EP03 failed: access denied";
        ep03.Evidence = "Error @ 2026-09-30 12:00 UTC";
        var ep05 = checks.Single(c => c.Id == "EP05");
        ep05.Findings = "Check EP05 timed out after 90s.";
        ep05.Evidence = "Timeout @ 2026-09-30 12:00 UTC";

        var html = HtmlReportGenerator.Generate(checks, new EnvironmentInfo(), 85, "B", 70, "C", tier: ReportTier.Executive);

        var section = html[html.IndexOf("<h2>Limitations</h2>", StringComparison.Ordinal)..];
        Assert.Contains("Coverage: 1 of 4 checks produced a scored result.", section);
        Assert.Contains("1 questionnaire checks are still waiting on an answer", section);
        Assert.Contains("Check EP03 failed: access denied", section);
        Assert.Contains(">Timed out</span>", section);
        Assert.Contains(">Error</span>", section);
        Assert.DoesNotContain(">EP01<", section);
    }

    [Fact]
    public void Html_Report_Has_No_Limitations_Section_When_Every_Check_Ran()
    {
        var checks = CreateChecks(("EP01", CheckStatus.Pass), ("EP02", CheckStatus.Fail));

        var html = HtmlReportGenerator.Generate(checks, new EnvironmentInfo(), 85, "B", 70, "C");

        Assert.DoesNotContain("<h2>Limitations</h2>", html);
    }

    [Fact]
    public void Compliance_Summary_Reports_Errors_And_Coverage()
    {
        var checks = CreateChecks(("EP01", CheckStatus.Pass), ("EP03", CheckStatus.Error), ("PS01", CheckStatus.NotAssessed), ("EP07", CheckStatus.NA));

        using var doc = JsonDocument.Parse(ComplianceSummaryExporter.Export(checks, new EnvironmentInfo(), 85, "B", 70, "C", 60, "D"));
        var counts = doc.RootElement.GetProperty("counts");
        var coverage = doc.RootElement.GetProperty("coverage");

        Assert.Equal(1, counts.GetProperty("na").GetInt32());
        Assert.Equal(1, counts.GetProperty("not_assessed").GetInt32());
        Assert.Equal(1, counts.GetProperty("error").GetInt32());
        Assert.Equal(3, coverage.GetProperty("applicable").GetInt32());
        Assert.Equal(1, coverage.GetProperty("scored").GetInt32());
        Assert.Equal(33.3, coverage.GetProperty("pct").GetDouble());
    }

    [Fact]
    public void Findings_Export_Reports_Coverage()
    {
        var checks = CreateChecks(("EP01", CheckStatus.Pass), ("EP03", CheckStatus.Error));
        checks.Single(c => c.Id == "EP03").Evidence = "Timeout @ 2026-09-30 12:00 UTC";

        using var doc = JsonDocument.Parse(JsonExporter.Export(checks, new EnvironmentInfo(), 85, "B", 70, "C", ScanProfileType.Full, 60, "D"));
        var coverage = doc.RootElement.GetProperty("coverage");

        Assert.Equal(2, coverage.GetProperty("applicable").GetInt32());
        Assert.Equal(1, coverage.GetProperty("scored").GetInt32());
        Assert.Equal(1, coverage.GetProperty("error").GetInt32());
        Assert.Equal(1, coverage.GetProperty("timed_out").GetInt32());
        Assert.Equal(50.0, coverage.GetProperty("pct").GetDouble());
    }

    private static ObservableCollection<CheckItemViewModel> CreateChecks(params (string id, CheckStatus status)[] items)
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var (id, status) in items)
        {
            var vm = CheckItemViewModel.FromMetadata(CheckCatalog.All[id]);
            vm.Status = status;
            checks.Add(vm);
        }
        return checks;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Repo root not found.");
    }
}

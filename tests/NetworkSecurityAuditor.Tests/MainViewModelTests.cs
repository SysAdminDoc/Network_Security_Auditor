using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class MainViewModelTests
{
    [Fact]
    public void IsScanning_Raises_Command_CanExecute_Changes()
    {
        var vm = new MainViewModel();
        var startChanges = 0;
        var stopChanges = 0;
        vm.StartScanCommand.CanExecuteChanged += (_, _) => startChanges++;
        vm.StopScanCommand.CanExecuteChanged += (_, _) => stopChanges++;

        Assert.True(vm.StartScanCommand.CanExecute(null));
        Assert.False(vm.StopScanCommand.CanExecute(null));

        vm.IsScanning = true;

        Assert.False(vm.StartScanCommand.CanExecute(null));
        Assert.True(vm.StopScanCommand.CanExecute(null));
        Assert.True(startChanges > 0);
        Assert.True(stopChanges > 0);
    }

    [Fact]
    public void Manual_Status_Changes_Update_Score_Counts()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var check = vm.Checks[0];

        Assert.Equal(0, vm.PassCount);
        Assert.Equal(0, vm.FailCount);
        Assert.Equal(0, vm.OverallScore);
        Assert.Equal(0, vm.NotApplicableCount);
        Assert.Equal(vm.Checks.Count, vm.NotAssessedCount);
        Assert.False(vm.HasAssessedChecks);
        Assert.Equal("\u2014", vm.Grade);
        Assert.Equal("Not scanned", vm.OverallScoreDisplay);

        check.Status = CheckStatus.Pass;

        Assert.Equal(1, vm.PassCount);
        Assert.Equal(0, vm.FailCount);
        Assert.Equal(vm.Checks.Count - 1, vm.NotAssessedCount);
        Assert.True(vm.HasAssessedChecks);
        Assert.Equal(100, vm.OverallScore);
        Assert.Equal("100/100", vm.OverallScoreDisplay);
        Assert.Equal("A", vm.Grade);

        check.Status = CheckStatus.Fail;

        Assert.Equal(0, vm.PassCount);
        Assert.Equal(1, vm.FailCount);
        Assert.True(vm.HasAssessedChecks);
        Assert.Equal(0, vm.OverallScore);
        Assert.Equal("0/100", vm.OverallScoreDisplay);
        Assert.Equal("F", vm.Grade);
    }

    [Fact]
    public void Load_Catalog_Selects_First_Check_And_Builds_Category_Summaries()
    {
        var vm = new MainViewModel();

        vm.LoadCheckCatalog();

        Assert.NotNull(vm.SelectedCheck);
        Assert.Equal(vm.Checks[0], vm.SelectedCheck);
        Assert.NotEmpty(vm.CategorySummaries);
        Assert.Equal(vm.Categories.Length - 1, vm.CategorySummaries.Count);
        Assert.Contains(vm.ActivityLog, line => line.Contains("Catalog loaded", StringComparison.Ordinal));
    }

    [Fact]
    public void Category_Summaries_Update_When_Status_Changes()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var category = vm.Checks[0].Category;
        var summary = vm.CategorySummaries.Single(s => s.Name == category);

        Assert.Equal("--", summary.ScoreDisplay);
        Assert.Equal(0, summary.AssessedCount);

        vm.Checks[0].Status = CheckStatus.Fail;

        Assert.Equal(1, summary.FailCount);
        Assert.Equal(1, summary.AssessedCount);
        Assert.Equal("0%", summary.ScoreDisplay);
        Assert.Equal("ProgressBad", summary.HealthBrushKey);

        vm.Checks[0].Status = CheckStatus.Pass;

        Assert.Equal(1, summary.PassCount);
        Assert.Equal(0, summary.FailCount);
        Assert.Equal("100%", summary.ScoreDisplay);
        Assert.Equal("ProgressGood", summary.HealthBrushKey);
    }

    [Fact]
    public void Filtered_Checks_Uses_Stable_View_And_Refreshes_Filters()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var view = vm.FilteredChecks;
        var check = vm.Checks[0];

        Assert.Same(view, vm.FilteredChecks);
        Assert.Equal(vm.Checks.Count, view.Cast<CheckItemViewModel>().Count());

        vm.SearchText = check.Id;
        Assert.Same(view, vm.FilteredChecks);
        Assert.Single(view.Cast<CheckItemViewModel>());
        Assert.Equal(check, vm.SelectedCheck);

        vm.StatusFilter = "Pass";
        Assert.Empty(view.Cast<CheckItemViewModel>());
        Assert.Null(vm.SelectedCheck);

        check.Status = CheckStatus.Pass;

        Assert.Same(view, vm.FilteredChecks);
        Assert.Contains(check, view.Cast<CheckItemViewModel>());
        Assert.Equal(check, vm.SelectedCheck);
    }

    [Fact]
    public void Export_Commands_Are_Gated_By_Assessment_And_Scan_State()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var exportCanExecute = new Func<bool>[]
        {
            () => vm.ExportSelectedCommand.CanExecute(null),
            () => vm.ExportHtmlCommand.CanExecute(null),
            () => vm.ExportPdfCommand.CanExecute(null),
            () => vm.ExportJsonCommand.CanExecute(null),
            () => vm.ExportCsvCommand.CanExecute(null),
            () => vm.ExportJsonlCommand.CanExecute(null),
            () => vm.ExportSarifCommand.CanExecute(null),
            () => vm.ExportNavigatorCommand.CanExecute(null),
            () => vm.ExportDefectDojoCommand.CanExecute(null),
            () => vm.ExportOcsfCommand.CanExecute(null),
            () => vm.ExportOscalCommand.CanExecute(null),
            () => vm.ExportIntuneCommand.CanExecute(null),
            () => vm.ExportComplianceSummaryCommand.CanExecute(null)
        };
        var htmlCanExecuteChanges = 0;
        vm.ExportHtmlCommand.CanExecuteChanged += (_, _) => htmlCanExecuteChanges++;

        Assert.All(exportCanExecute, canExecute => Assert.False(canExecute()));

        vm.Checks[0].Status = CheckStatus.Pass;

        Assert.All(exportCanExecute, canExecute => Assert.True(canExecute()));
        Assert.True(htmlCanExecuteChanges > 0);

        vm.IsScanning = true;

        Assert.All(exportCanExecute, canExecute => Assert.False(canExecute()));

        vm.IsScanning = false;

        Assert.All(exportCanExecute, canExecute => Assert.True(canExecute()));
    }

    [Fact]
    public async Task Export_Selected_Command_Writes_Cmmc_And_Siem_Outputs_To_Selected_Folder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nsa-gui-export-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var vm = new MainViewModel();
            vm.LoadCheckCatalog();
            vm.ExportOutputFolder = dir;
            foreach (var check in vm.Checks.Take(5))
            {
                check.Status = CheckStatus.Pass;
                check.Findings = $"Finding for {check.Id}";
                check.Evidence = $"Evidence for {check.Id}";
            }

            vm.SelectedExportFormat = vm.ExportFormats.Single(f => f.Kind == ExportFormatKind.CmmcJson);
            await vm.ExportSelectedCommand.ExecuteAsync(null);
            var cmmcJson = Assert.Single(Directory.GetFiles(dir, "*_cmmc.json"));
            Assert.Contains("\"report_type\": \"cmmc_self_assessment\"", await File.ReadAllTextAsync(cmmcJson));

            vm.SelectedExportFormat = vm.ExportFormats.Single(f => f.Kind == ExportFormatKind.CmmcHtml);
            await vm.ExportSelectedCommand.ExecuteAsync(null);
            var cmmcHtml = Assert.Single(Directory.GetFiles(dir, "*_cmmc.html"));
            Assert.Contains("CMMC Level 2 Self-Assessment Report", await File.ReadAllTextAsync(cmmcHtml));

            vm.SelectedExportFormat = vm.ExportFormats.Single(f => f.Kind == ExportFormatKind.SiemContentPack);
            await vm.ExportSelectedCommand.ExecuteAsync(null);
            var siemDir = Assert.Single(Directory.GetDirectories(dir, "*_siem_pack"));
            Assert.True(File.Exists(Path.Combine(siemDir, "field_mapping.json")));
            Assert.True(File.Exists(Path.Combine(siemDir, "sentinel_table.json")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task StartScan_Marks_Only_Active_Check_And_Clears_On_Cancel()
    {
        MainViewModel vm = null!;
        var secondCheckStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var runningSnapshots = new List<string>();

        vm = new MainViewModel(async (_, _, progress, ct, startedProgress) =>
        {
            startedProgress?.Report(("EP01", 1, 2));
            runningSnapshots.Add(RunningIds(vm));

            progress?.Report(("EP01", PassingResult("EP01")));
            runningSnapshots.Add(RunningIds(vm));

            startedProgress?.Report(("EP02", 2, 2));
            runningSnapshots.Add(RunningIds(vm));
            secondCheckStarted.SetResult(true);

            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new Dictionary<string, CheckResult>();
        });
        vm.LoadCheckCatalog();
        vm.SelectedProfile = ScanProfileType.Quick;

        var scanTask = vm.StartScanCommand.ExecuteAsync(null);
        await secondCheckStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("EP01", runningSnapshots[0]);
        Assert.Equal("", runningSnapshots[1]);
        Assert.Equal("EP02", runningSnapshots[2]);
        Assert.Single(vm.Checks, c => c.IsRunning);
        Assert.True(vm.Checks.Single(c => c.Id == "EP02").IsRunning);

        vm.StopScanCommand.Execute(null);
        await scanTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(vm.IsScanning);
        Assert.DoesNotContain(vm.Checks, c => c.IsRunning);
        Assert.Equal(CheckStatus.Pass, vm.Checks.Single(c => c.Id == "EP01").Status);
        Assert.Contains("Scan cancelled", vm.ScanStatus);
    }

    private static string RunningIds(MainViewModel vm)
    {
        return string.Join(",", vm.Checks.Where(c => c.IsRunning).Select(c => c.Id).OrderBy(id => id));
    }

    private static CheckResult PassingResult(string checkId) => new()
    {
        Status = CheckStatus.Pass,
        Findings = $"{checkId} passed",
        Evidence = "Synthetic test result"
    };
}

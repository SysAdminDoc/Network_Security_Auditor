using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;
using System.Globalization;

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

        Assert.False(vm.StartScanCommand.CanExecute(null));
        Assert.False(vm.StopScanCommand.CanExecute(null));
        Assert.True(vm.CanEditScanOptions);
        Assert.Contains("still running", vm.StartScanHelpText);
        Assert.Equal("No scan is currently running.", vm.StopScanHelpText);
        Assert.Contains("Current profile: Full", vm.ScanProfileHelpText);
        Assert.Contains("Redacts host", vm.PrivacyModeHelpText);

        vm.IsEnvironmentReady = true;

        Assert.True(vm.StartScanCommand.CanExecute(null));
        Assert.Contains("Run the Full profile", vm.StartScanHelpText);

        vm.IsScanning = true;

        Assert.False(vm.StartScanCommand.CanExecute(null));
        Assert.True(vm.StopScanCommand.CanExecute(null));
        Assert.False(vm.CanEditScanOptions);
        Assert.Equal("A scan is already running.", vm.StartScanHelpText);
        Assert.Contains("Cancel the running scan", vm.StopScanHelpText);
        Assert.Contains("locked", vm.ScanProfileHelpText);
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
        Assert.Equal("\u2014", vm.RansomwareGradeDisplay);
        Assert.Equal("Pending", vm.RansomwareScoreDisplay);
        Assert.Equal("StatusNeutral", vm.RansomwareBrushKey);
        Assert.Equal("\u2014", vm.DomainMaturityGradeDisplay);
        Assert.Equal("Pending", vm.DomainMaturityScoreDisplay);
        Assert.Equal("StatusNeutral", vm.DomainMaturityBrushKey);

        check.Status = CheckStatus.Pass;

        Assert.Equal(1, vm.PassCount);
        Assert.Equal(0, vm.FailCount);
        Assert.Equal(vm.Checks.Count - 1, vm.NotAssessedCount);
        Assert.True(vm.HasAssessedChecks);
        Assert.Equal(100, vm.OverallScore);
        Assert.Equal("100/100", vm.OverallScoreDisplay);
        Assert.Equal("A", vm.Grade);
        Assert.EndsWith("/100", vm.RansomwareScoreDisplay, StringComparison.Ordinal);
        Assert.NotEqual("StatusNeutral", vm.RansomwareBrushKey);

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
        Assert.Equal(vm.Checks.Count, vm.VisibleCheckCount);
        Assert.True(vm.HasVisibleChecks);
        Assert.False(vm.HasActiveFilters);
        Assert.True(vm.IsSearchWatermarkVisible);

        vm.SearchText = check.Id;
        Assert.Same(view, vm.FilteredChecks);
        Assert.Single(view.Cast<CheckItemViewModel>());
        Assert.Equal(check, vm.SelectedCheck);
        Assert.Equal(1, vm.VisibleCheckCount);
        Assert.True(vm.HasActiveFilters);
        Assert.False(vm.IsSearchWatermarkVisible);

        vm.StatusFilter = "Pass";
        Assert.Empty(view.Cast<CheckItemViewModel>());
        Assert.Null(vm.SelectedCheck);
        Assert.Equal(0, vm.VisibleCheckCount);
        Assert.True(vm.HasNoVisibleChecks);
        Assert.Equal("No checks match this view", vm.FilterEmptyStateTitle);
        Assert.Contains("Clear filters", vm.FilterEmptyStateDetail, StringComparison.Ordinal);

        check.Status = CheckStatus.Pass;

        Assert.Same(view, vm.FilteredChecks);
        Assert.Contains(check, view.Cast<CheckItemViewModel>());
        Assert.Equal(check, vm.SelectedCheck);

        vm.ClearFiltersCommand.Execute(null);

        Assert.Equal("All", vm.SelectedCategory);
        Assert.Equal("", vm.SearchText);
        Assert.Equal("All", vm.StatusFilter);
        Assert.Equal(vm.Checks.Count, vm.VisibleCheckCount);
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
        Assert.Equal("Run a scan or mark at least one check before exporting.", vm.ExportAvailabilityText);

        vm.Checks[0].Status = CheckStatus.Pass;

        Assert.All(exportCanExecute, canExecute => Assert.True(canExecute()));
        Assert.Equal("Ready to export HTML report.", vm.ExportAvailabilityText);
        Assert.True(htmlCanExecuteChanges > 0);

        vm.ExportOutputFolder = "";
        Assert.All(exportCanExecute, canExecute => Assert.False(canExecute()));
        Assert.Equal("Choose an export folder before exporting.", vm.ExportAvailabilityText);

        vm.ExportOutputFolder = Path.Combine(Path.GetTempPath(), "nsa-export");
        vm.IsScanning = true;

        Assert.All(exportCanExecute, canExecute => Assert.False(canExecute()));
        Assert.Equal("Export pauses while a scan is running.", vm.ExportAvailabilityText);

        vm.IsScanning = false;

        Assert.All(exportCanExecute, canExecute => Assert.True(canExecute()));

        vm.IsExporting = true;

        Assert.All(exportCanExecute, canExecute => Assert.False(canExecute()));
        Assert.Equal("Exporting HTML report...", vm.ExportAvailabilityText);
        Assert.Equal("Exporting HTML report...", vm.ScanReadinessText);

        vm.IsExporting = false;

        Assert.All(exportCanExecute, canExecute => Assert.True(canExecute()));
    }

    [Fact]
    public void Score_And_Readiness_Copy_Stay_Compact_For_The_Shell()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();

        Assert.Equal("Ready for pre-flight", vm.ScoreSubtitle);
        Assert.Equal("Preparing the audit workspace", vm.ScanReadinessText);
        Assert.DoesNotContain(ScanProfileType.Cloud, vm.AvailableProfiles);

        vm.IsEnvironmentReady = true;
        vm.PreflightPassedCount = 4;
        vm.PreflightTotalCount = 7;

        Assert.Equal("Pre-flight 4/7 passed", vm.ScoreSubtitle);
        Assert.Equal("Ready with 3 pre-flight advisories", vm.ScanReadinessText);
        Assert.Equal("ProgressMid", vm.ReadinessBrushKey);

        vm.ScanStatus = "Pre-flight complete: 4/7 checks passed";

        Assert.Equal("Ready", vm.ScanStatusHeadline);

        vm.Checks[0].Status = CheckStatus.Pass;

        Assert.Equal($"1 assessed - {vm.Checks.Count - 1} open", vm.ScoreSubtitle);
        Assert.Equal("1 assessed - export ready", vm.ScanReadinessText);
    }

    [Fact]
    public void Status_Badge_Foreground_Stays_Readable_For_Neutral_Badges()
    {
        var check = CheckItemViewModel.FromMetadata(CheckCatalog.All["EP01"]);

        Assert.Equal("BadgeBg", check.StatusBrushKey);
        Assert.Equal("TextSecondary", check.StatusForegroundBrushKey);

        check.Status = CheckStatus.Pass;

        Assert.Equal("ProgressGood", check.StatusBrushKey);
        Assert.Equal("WindowBg", check.StatusForegroundBrushKey);
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

            vm.Checks[0].Status = CheckStatus.Fail;
            vm.Checks[0].Notes = "Owner accepted remediation tracking.";
            vm.SelectedExportFormat = vm.ExportFormats.Single(f => f.Kind == ExportFormatKind.OscalPoam);
            await vm.ExportSelectedCommand.ExecuteAsync(null);
            var poamJson = Assert.Single(Directory.GetFiles(dir, "*_oscal_poam.json"));
            Assert.Contains("\"plan-of-action-and-milestones\"", await File.ReadAllTextAsync(poamJson));

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
        vm.IsEnvironmentReady = true;
        vm.SelectedProfile = ScanProfileType.Quick;
        var userSelection = vm.SelectedCheck;

        var scanTask = vm.StartScanCommand.ExecuteAsync(null);
        await secondCheckStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("EP01", runningSnapshots[0]);
        Assert.Equal("", runningSnapshots[1]);
        Assert.Equal("EP02", runningSnapshots[2]);
        Assert.Single(vm.Checks, c => c.IsRunning);
        Assert.True(vm.Checks.Single(c => c.Id == "EP02").IsRunning);
        Assert.Same(userSelection, vm.SelectedCheck);

        vm.StopScanCommand.Execute(null);
        await scanTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(vm.IsScanning);
        Assert.DoesNotContain(vm.Checks, c => c.IsRunning);
        Assert.Equal(CheckStatus.Pass, vm.Checks.Single(c => c.Id == "EP01").Status);
        Assert.Contains("Scan cancelled", vm.ScanStatus);
    }

    [Fact]
    public async Task StartScan_Stops_When_Profile_Has_No_Applicable_Checks()
    {
        var runnerCalled = false;
        var vm = new MainViewModel((_, _, _, _, _) =>
        {
            runnerCalled = true;
            return Task.FromResult(new Dictionary<string, CheckResult>());
        });
        vm.LoadCheckCatalog();
        vm.IsEnvironmentReady = true;
        vm.Environment = new EnvironmentInfo { IsDomainJoined = false, ComputerName = "WORKGROUP-PC" };
        vm.SelectedProfile = ScanProfileType.ADOnly;

        await vm.StartScanCommand.ExecuteAsync(null);

        Assert.False(runnerCalled);
        Assert.False(vm.IsScanning);
        Assert.Equal(0, vm.ScanProgressPercent);
        Assert.Contains("No checks in the ADOnly profile apply", vm.ScanStatus);
    }

    [Fact]
    public async Task StartScan_Generates_And_Opens_Html_Report_When_Complete()
    {
        var openedReports = new List<string>();
        var dir = Path.Combine(Path.GetTempPath(), "nsa-auto-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var vm = new MainViewModel((_, _, progress, _, startedProgress) =>
            {
                startedProgress?.Report(("EP01", 1, 1));
                progress?.Report(("EP01", PassingResult("EP01")));
                return Task.FromResult(new Dictionary<string, CheckResult>
                {
                    ["EP01"] = PassingResult("EP01")
                });
            }, openedReports.Add);
            vm.LoadCheckCatalog();
            vm.IsEnvironmentReady = true;
            vm.SelectedProfile = ScanProfileType.Quick;
            vm.ExportOutputFolder = dir;

            await vm.StartScanCommand.ExecuteAsync(null);

            var openedReport = Assert.Single(openedReports);
            Assert.True(File.Exists(openedReport));
            Assert.StartsWith(dir, openedReport, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("SecurityAudit_", Path.GetFileName(openedReport));
            Assert.Contains("Report generated and opened", vm.ScanStatus);
            Assert.Contains(vm.ActivityLog, entry => entry.Contains("HTML report generated and opened", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task StartScan_Failure_Produces_Recoverable_Error_State()
    {
        var openedReports = new List<string>();
        var vm = new MainViewModel((_, _, _, _, startedProgress) =>
        {
            startedProgress?.Report(("EP01", 1, 1));
            throw new InvalidOperationException("Synthetic runner failure");
        }, openedReports.Add);
        vm.LoadCheckCatalog();
        vm.IsEnvironmentReady = true;
        vm.SelectedProfile = ScanProfileType.Quick;

        await vm.StartScanCommand.ExecuteAsync(null);

        Assert.False(vm.IsScanning);
        Assert.True(vm.StartScanCommand.CanExecute(null));
        Assert.False(vm.StopScanCommand.CanExecute(null));
        Assert.Contains("Scan failed", vm.ScanStatus, StringComparison.Ordinal);
        Assert.Contains(vm.ActivityLog, entry => entry.Contains("Synthetic runner failure", StringComparison.Ordinal));
        Assert.Contains(vm.ActivityLog, entry => entry.Contains("Crash log:", StringComparison.Ordinal));
        Assert.Empty(openedReports);
        Assert.DoesNotContain(vm.Checks, check => check.IsRunning);
    }

    [Fact]
    public void ApplyAuditState_Restores_Profile_And_Clears_Invalid_Due_Date()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var check = vm.Checks.Single(c => c.Id == "EP01");
        check.RemediationDueDate = new DateTime(2026, 7, 9);

        var restored = vm.ApplyAuditState(new AuditState
        {
            ScanProfile = "Quick",
            Theme = "Catppuccin Mocha",
            Checks =
            [
                new CheckState
                {
                    Id = "EP01",
                    Status = CheckStatus.Fail,
                    Findings = "Loaded finding",
                    RemediationDueDate = "not-a-date"
                }
            ]
        });

        Assert.Equal(1, restored);
        Assert.Equal(ScanProfileType.Quick, vm.SelectedProfile);
        Assert.Equal("Catppuccin Mocha", vm.SelectedTheme);
        Assert.Equal(CheckStatus.Fail, check.Status);
        Assert.Equal("Loaded finding", check.Findings);
        Assert.Null(check.RemediationDueDate);
    }

    [Fact]
    public void ApplyAuditState_Parses_Due_Date_With_Invariant_Format()
    {
        var originalCulture = Thread.CurrentThread.CurrentCulture;
        var originalUiCulture = Thread.CurrentThread.CurrentUICulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("ar-SA");

            var vm = new MainViewModel();
            vm.LoadCheckCatalog();
            var check = vm.Checks.Single(c => c.Id == "EP01");

            vm.ApplyAuditState(new AuditState
            {
                Checks =
                [
                    new CheckState
                    {
                        Id = "EP01",
                        Status = CheckStatus.Partial,
                        RemediationDueDate = "2026-07-09"
                    }
                ]
            });

            Assert.Equal(new DateTime(2026, 7, 9), check.RemediationDueDate);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = originalCulture;
            Thread.CurrentThread.CurrentUICulture = originalUiCulture;
        }
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

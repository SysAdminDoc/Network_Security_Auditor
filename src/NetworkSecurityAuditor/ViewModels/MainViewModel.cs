using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;

namespace NetworkSecurityAuditor.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private static readonly ExportFormatOption[] DefaultExportFormats =
    [
        new(ExportFormatKind.Html, "HTML report", "", "html"),
        new(ExportFormatKind.Pdf, "PDF report", "", "pdf"),
        new(ExportFormatKind.Json, "Findings JSON", "", "json"),
        new(ExportFormatKind.Csv, "Findings CSV", "", "csv"),
        new(ExportFormatKind.Jsonl, "SIEM JSONL", "_siem", "jsonl"),
        new(ExportFormatKind.Sarif, "SARIF", "", "sarif"),
        new(ExportFormatKind.Navigator, "ATT&CK Navigator", "_navigator", "json"),
        new(ExportFormatKind.DefectDojo, "DefectDojo JSON", "_defectdojo", "json"),
        new(ExportFormatKind.Ocsf, "OCSF JSONL", "_ocsf", "jsonl"),
        new(ExportFormatKind.Oscal, "OSCAL JSON", "_oscal", "json"),
        new(ExportFormatKind.Intune, "Intune JSON", "_intune", "json"),
        new(ExportFormatKind.ComplianceSummary, "Compliance summary JSON", "_summary", "json"),
        new(ExportFormatKind.SiemContentPack, "SIEM content pack", "_siem_pack", "", IsFolderExport: true),
        new(ExportFormatKind.CmmcHtml, "CMMC HTML", "_cmmc", "html"),
        new(ExportFormatKind.CmmcJson, "CMMC JSON", "_cmmc", "json")
    ];

    private CancellationTokenSource? _scanCts;
    private readonly RunChecksAsync _runChecksAsync;

    internal delegate Task<Dictionary<string, CheckResult>> RunChecksAsync(
        EnvironmentInfo env,
        AuditOptions options,
        IProgress<(string checkId, CheckResult result)>? progress,
        CancellationToken ct,
        IProgress<(string checkId, int index, int total)>? startedProgress);

    public ObservableCollection<CheckItemViewModel> Checks { get; } = [];

    public ObservableCollection<CategorySummaryViewModel> CategorySummaries { get; } = [];

    public ObservableCollection<CategorySummaryViewModel> CategoryRailItems { get; } = [];

    public ObservableCollection<string> ActivityLog { get; } = [];

    public ICollectionView FilteredChecks { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _selectedCategory = "All";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(IsSearchWatermarkVisible), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _searchText = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _statusFilter = "All";

    [ObservableProperty]
    private CheckItemViewModel? _selectedCheck;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopScanCommand))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ExportAvailabilityText), nameof(ScanProgressDisplay), nameof(ScanStatusHeadline))]
    private bool _isScanning;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScanReadinessText), nameof(ExportAvailabilityText), nameof(ScanStatusHeadline))]
    private bool _isExporting;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private string _scanStatus = "Ready";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScanProgressDisplay), nameof(ScanStatusHeadline))]
    private double _scanProgressPercent;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProfileSummary))]
    private ScanProfileType _selectedProfile = ScanProfileType.Full;

    [ObservableProperty]
    private bool _privacyMode;

    [ObservableProperty]
    private string _selectedTheme = "Catppuccin Mocha";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Grade), nameof(GradeBrushKey), nameof(OverallScoreDisplay), nameof(RiskPostureLabel))]
    private int _overallScore;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount), nameof(AssessedChecksDisplay), nameof(OutcomeSummaryDisplay))]
    private int _passCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount), nameof(AssessedChecksDisplay), nameof(OutcomeSummaryDisplay))]
    private int _failCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AssessedCount), nameof(AssessedChecksDisplay), nameof(OutcomeSummaryDisplay))]
    private int _partialCount;

    [ObservableProperty]
    private int _naCount;

    [ObservableProperty]
    private int _notApplicableCount;

    [ObservableProperty]
    private int _notAssessedCount;

    [ObservableProperty]
    private int _ransomwareScore;

    [ObservableProperty]
    private string _ransomwareGrade = "N/A";

    [ObservableProperty]
    private int _domainMaturityScore;

    [ObservableProperty]
    private string _domainMaturityGrade = "N/A";

    public string[] Categories { get; private set; } = ["All"];

    public string[] StatusFilters { get; } = ["All", "Pass", "Partial", "Fail", "N/A", "Not Assessed"];

    public string[] AvailableThemes { get; } = ["Catppuccin Mocha"];

    public ScanProfileType[] AvailableProfiles { get; } = Enum.GetValues<ScanProfileType>();

    public IReadOnlyList<ExportFormatOption> ExportFormats { get; } = DefaultExportFormats;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExportAvailabilityText))]
    private ExportFormatOption _selectedExportFormat = DefaultExportFormats[0];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExportAvailabilityText))]
    private string _exportOutputFolder = Path.Combine(
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyDocuments),
        "NetworkSecurityAuditor");

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasVisibleChecks), nameof(HasNoVisibleChecks), nameof(VisibleChecksDisplay), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private int _visibleCheckCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ReadinessDisplay))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private int _preflightPassedCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ReadinessDisplay))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private int _preflightTotalCount;

    public MainViewModel() : this(DefaultRunChecksAsync)
    {
    }

    internal MainViewModel(RunChecksAsync runChecksAsync)
    {
        _runChecksAsync = runChecksAsync;
        FilteredChecks = CollectionViewSource.GetDefaultView(Checks);
        FilteredChecks.Filter = FilterCheck;
    }

    private static Task<Dictionary<string, CheckResult>> DefaultRunChecksAsync(
        EnvironmentInfo env,
        AuditOptions options,
        IProgress<(string checkId, CheckResult result)>? progress,
        CancellationToken ct,
        IProgress<(string checkId, int index, int total)>? startedProgress)
    {
        var runner = new CheckRunner(CheckRegistry.GetAllChecks());
        return runner.RunAsync(env, options, progress, ct, startedProgress);
    }

    private bool FilterCheck(object item)
    {
        if (item is not CheckItemViewModel check)
            return false;

        if (SelectedCategory != "All" && check.Category != SelectedCategory)
            return false;

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim();
            if (!check.Id.Contains(search, StringComparison.OrdinalIgnoreCase) &&
                !check.Label.Contains(search, StringComparison.OrdinalIgnoreCase) &&
                !check.Category.Contains(search, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return StatusFilter switch
        {
            "Pass" => check.Status == CheckStatus.Pass,
            "Partial" => check.Status == CheckStatus.Partial,
            "Fail" => check.Status == CheckStatus.Fail,
            "N/A" => check.Status == CheckStatus.NA,
            "Not Assessed" => check.Status == CheckStatus.NotAssessed,
            _ => true
        };
    }

    partial void OnSelectedCategoryChanged(string value)
    {
        RefreshFilteredChecks();
    }

    partial void OnSearchTextChanged(string value)
    {
        RefreshFilteredChecks();
    }

    partial void OnStatusFilterChanged(string value)
    {
        RefreshFilteredChecks();
    }

    public bool HasAssessedChecks => Checks.Any(c => c.Status is CheckStatus.Pass or CheckStatus.Partial or CheckStatus.Fail);

    public bool HasVisibleChecks => VisibleCheckCount > 0;

    public bool HasNoVisibleChecks => !HasVisibleChecks;

    public bool HasActiveFilters =>
        SelectedCategory != "All" ||
        StatusFilter != "All" ||
        !string.IsNullOrWhiteSpace(SearchText);

    public bool IsSearchWatermarkVisible => string.IsNullOrWhiteSpace(SearchText);

    public string VisibleChecksDisplay => Checks.Count == 0
        ? "No checks loaded"
        : $"{VisibleCheckCount}/{Checks.Count} visible";

    public string FilterEmptyStateTitle => Checks.Count == 0
        ? "No checks loaded"
        : "No checks match this view";

    public string FilterEmptyStateDetail => HasActiveFilters
        ? "Clear filters or adjust category and status."
        : "Load the check catalog to begin.";

    public string Grade => HasAssessedChecks ? RiskScoreEngine.GradeFromScore(OverallScore) : "\u2014";

    public string OverallScoreDisplay => HasAssessedChecks ? $"{OverallScore}/100" : "Not scanned";

    public string ScoreSubtitle
    {
        get
        {
            if (IsScanning)
                return ScanStatus;

            if (HasAssessedChecks)
                return $"{PassCount + PartialCount + FailCount} assessed - {NotAssessedCount} open";

            return PreflightTotalCount > 0
                ? $"Pre-flight {PreflightPassedCount}/{PreflightTotalCount} passed"
                : "Ready for pre-flight";
        }
    }

    public int AssessedCount => PassCount + PartialCount + FailCount;

    public string AssessedChecksDisplay => Checks.Count == 0
        ? "0 / 0"
        : $"{AssessedCount} / {Checks.Count}";

    public string OutcomeSummaryDisplay => $"{PassCount} pass - {PartialCount} partial - {FailCount} fail";

    public string ProfileSummary => $"{SelectedProfile} profile";

    public string ReadinessDisplay => PreflightTotalCount > 0
        ? $"{PreflightPassedCount}/{PreflightTotalCount} ready"
        : "Pre-flight pending";

    public string ScanProgressDisplay => IsScanning || ScanProgressPercent > 0
        ? $"{ScanProgressPercent:0}%"
        : "Idle";

    public string ScanStatusHeadline
    {
        get
        {
            if (IsScanning)
                return ScanProgressPercent > 0 ? $"Scanning {ScanProgressPercent:0}%" : "Scanning";

            if (IsExporting)
                return "Exporting report";

            if (ScanStatus.StartsWith("Pre-flight complete:", StringComparison.OrdinalIgnoreCase))
                return "Ready";

            if (ScanStatus.Contains(" exported", StringComparison.OrdinalIgnoreCase))
                return "Export complete";

            if (ScanStatus.StartsWith("State loaded", StringComparison.OrdinalIgnoreCase))
                return "State loaded";

            if (ScanStatus.StartsWith("State saved", StringComparison.OrdinalIgnoreCase))
                return "State saved";

            return CompactStatus(ScanStatus, 30);
        }
    }

    public string RiskPostureLabel
    {
        get
        {
            if (!HasAssessedChecks)
                return "Not scanned";

            return Grade switch
            {
                "A" => "Strong posture",
                "B" => "Managed risk",
                "C" => "Moderate risk",
                "D" => "High risk",
                "F" => "Critical risk",
                _ => "Unknown"
            };
        }
    }

    public string ScanReadinessText
    {
        get
        {
            if (IsScanning)
                return ScanStatus;

            if (IsExporting)
                return $"Exporting {SelectedExportFormat.DisplayName}...";

            if (HasAssessedChecks)
                return $"{PassCount + PartialCount + FailCount} assessed - export ready";

            return PreflightTotalCount > 0
                ? "Ready to scan"
                : "Ready to run local audit checks";
        }
    }

    private static string CompactStatus(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
            return string.IsNullOrWhiteSpace(value) ? "Ready" : value;

        return value[..Math.Max(0, maxLength - 3)].TrimEnd() + "...";
    }

    public string ExportAvailabilityText
    {
        get
        {
            if (IsScanning)
                return "Export pauses while a scan is running.";

            if (IsExporting)
                return $"Exporting {SelectedExportFormat.DisplayName}...";

            if (string.IsNullOrWhiteSpace(ExportOutputFolder))
                return "Choose an export folder before exporting.";

            return HasAssessedChecks
                ? $"Ready to export {SelectedExportFormat.DisplayName}."
                : "Run a scan or mark at least one check before exporting.";
        }
    }

    public string GradeBrushKey => HasAssessedChecks ? Grade switch
    {
        "A" => "ProgressGood",
        "B" => "GradeB",
        "C" => "ProgressMid",
        "D" => "SeverityHigh",
        "F" => "ProgressBad",
        _ => "StatusNeutral"
    } : "StatusNeutral";

    private EnvironmentInfo _environment = new();

    public EnvironmentInfo Environment
    {
        get => _environment;
        set
        {
            if (SetProperty(ref _environment, value))
            {
                OnPropertyChanged(nameof(TargetDisplay));
                OnPropertyChanged(nameof(EnvironmentBadge));
            }
        }
    }

    public string TargetDisplay => Environment.IsDomainJoined && !string.IsNullOrWhiteSpace(Environment.DomainName)
        ? $"{Environment.DomainName} / {Environment.ComputerName}"
        : Environment.ComputerName;

    public string EnvironmentBadge => Environment.IsDomainJoined
        ? "Domain joined"
        : Environment.JoinType;

    [ObservableProperty]
    private string _preflightSummary = "";

    public void RunPreflight()
    {
        var results = Services.PreflightChecker.Run(Environment);
        var passed = results.Count(r => r.Passed);
        var lines = results.Select(r => $"{(r.Passed ? "PASS" : "WARN")}  {r.Name}: {r.Detail}");
        PreflightPassedCount = passed;
        PreflightTotalCount = results.Count;
        PreflightSummary = $"Pre-flight: {passed}/{results.Count} passed\n{string.Join("\n", lines)}";
        ScanStatus = $"Pre-flight complete: {passed}/{results.Count} checks passed";
        AppendActivity($"Pre-flight complete: {passed}/{results.Count} checks passed");
        foreach (var line in lines)
        {
            AppendActivity(line);
        }
    }

    public void LoadCheckCatalog()
    {
        DetachCheckStatusHandlers();
        Checks.Clear();
        CategorySummaries.Clear();
        CategoryRailItems.Clear();
        foreach (var meta in CheckCatalog.All.Values.OrderBy(m => m.Id))
        {
            var check = CheckItemViewModel.FromMetadata(meta);
            check.PropertyChanged += OnCheckPropertyChanged;
            Checks.Add(check);
        }

        Categories = ["All", .. CheckCatalog.Categories];
        OnPropertyChanged(nameof(Categories));
        CategoryRailItems.Add(new CategorySummaryViewModel { Name = "All" });
        foreach (var category in CheckCatalog.Categories)
        {
            var summary = new CategorySummaryViewModel { Name = category };
            CategorySummaries.Add(summary);
            CategoryRailItems.Add(summary);
        }

        SelectedCheck = Checks.FirstOrDefault();
        RefreshFilteredChecks(preserveSelection: true);
        UpdateScoreCounts();
        AppendActivity($"Catalog loaded: {Checks.Count} checks across {CategorySummaries.Count} categories");
    }

    private void DetachCheckStatusHandlers()
    {
        foreach (var check in Checks)
        {
            check.PropertyChanged -= OnCheckPropertyChanged;
        }
    }

    private void OnCheckPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(CheckItemViewModel.Status)) return;

        UpdateScoreCounts();
        RefreshFilteredChecks(preserveSelection: true);
    }

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        if (IsScanning) return;

        _scanCts = new CancellationTokenSource();
        IsScanning = true;
        ScanStatus = "Scanning...";
        ScanProgressPercent = 0;
        AppendActivity($"Scan started: {SelectedProfile} profile");

        var options = new AuditOptions
        {
            ScanProfile = SelectedProfile
        };

        var completed = 0;
        var runningTotal = 0;
        var checkLookup = Checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var unsupportedProfile = false;

        var startedProgress = new InlineProgress<(string checkId, int index, int total)>(update =>
        {
            runningTotal = update.total;
            SetRunningCheck(update.checkId);
            ScanProgressPercent = update.total > 0
                ? (double)(update.index - 1) / update.total * 100
                : 0;

            if (checkLookup.TryGetValue(update.checkId, out var vm))
            {
                vm.IsRunning = true;
                SelectedCheck = vm;
                ScanStatus = $"Running {update.checkId}: {vm.Label} ({update.index}/{update.total})";
                AppendActivity($"Running {update.checkId}: {vm.Label}");
            }
            else
            {
                ScanStatus = $"Running {update.checkId} ({update.index}/{update.total})";
                AppendActivity($"Running {update.checkId}");
            }
        });

        var progress = new InlineProgress<(string checkId, CheckResult result)>(update =>
        {
            var nextCompleted = completed + 1;
            if (checkLookup.TryGetValue(update.checkId, out var vm))
            {
                vm.Status = update.result.Status;
                vm.Findings = update.result.Findings;
                vm.Evidence = update.result.Evidence;
                vm.DurationMs = update.result.Duration.TotalMilliseconds;
                vm.IsRunning = false;
                ScanStatus = $"Completed {update.checkId}: {vm.Label} ({nextCompleted}/{runningTotal})";
                AppendActivity($"Completed {update.checkId}: {update.result.Status}");
            }
            else
            {
                ScanStatus = $"Completed {update.checkId} ({nextCompleted}/{runningTotal})";
                AppendActivity($"Completed {update.checkId}: {update.result.Status}");
            }

            completed = nextCompleted;
            ScanProgressPercent = runningTotal > 0
                ? (double)completed / runningTotal * 100
                : 0;
            UpdateScoreCounts();
        });

        ClearRunningChecks();

        try
        {
            var profileIds = ScanProfiles.Resolve(options.ScanProfile);
            runningTotal = profileIds.Length;
            if (profileIds.Length == 0)
            {
                unsupportedProfile = true;
                ScanStatus = $"{options.ScanProfile} profile is not available in this preview. No local or Active Directory checks were run.";
                AppendActivity(ScanStatus);
                ScanProgressPercent = 0;
                return;
            }

            var results = await _runChecksAsync(Environment, options, progress, _scanCts.Token, startedProgress);
            completed = results.Count;
        }
        catch (OperationCanceledException)
        {
            // User cancelled
        }
        finally
        {
            ClearRunningChecks();
            IsScanning = false;
            var total = runningTotal;
            if (!unsupportedProfile)
            {
                ScanStatus = _scanCts.Token.IsCancellationRequested
                    ? $"Scan cancelled ({completed}/{total} completed)"
                    : $"Scan complete ({completed}/{total} checks)";
                AppendActivity(ScanStatus);
                if (!_scanCts.Token.IsCancellationRequested && total > 0)
                    ScanProgressPercent = 100;
            }
            _scanCts.Dispose();
            _scanCts = null;

            StartScanCommand.NotifyCanExecuteChanged();
            StopScanCommand.NotifyCanExecuteChanged();
        }
    }

    private bool CanStartScan() => !IsScanning;

    [RelayCommand(CanExecute = nameof(CanStopScan))]
    private void StopScan()
    {
        _scanCts?.Cancel();
        ScanStatus = "Cancelling...";
        AppendActivity("Scan cancellation requested");
    }

    private bool CanStopScan() => IsScanning;

    private void SetRunningCheck(string checkId)
    {
        foreach (var checkVm in Checks)
        {
            checkVm.IsRunning = string.Equals(checkVm.Id, checkId, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void ClearRunningChecks()
    {
        foreach (var checkVm in Checks)
        {
            checkVm.IsRunning = false;
        }
    }

    partial void OnIsScanningChanged(bool value)
    {
        NotifyExportCommandCanExecuteChanged();
        OnPropertyChanged(nameof(ExportAvailabilityText));
    }

    partial void OnIsExportingChanged(bool value) => NotifyExportCommandCanExecuteChanged();

    partial void OnSelectedExportFormatChanged(ExportFormatOption value) => NotifyExportCommandCanExecuteChanged();

    partial void OnExportOutputFolderChanged(string value) => NotifyExportCommandCanExecuteChanged();

    private bool CanExport() => !IsScanning && !IsExporting && HasAssessedChecks && !string.IsNullOrWhiteSpace(ExportOutputFolder);

    private void NotifyExportCommandCanExecuteChanged()
    {
        ExportSelectedCommand.NotifyCanExecuteChanged();
        ExportHtmlCommand.NotifyCanExecuteChanged();
        ExportJsonCommand.NotifyCanExecuteChanged();
        ExportCsvCommand.NotifyCanExecuteChanged();
        ExportJsonlCommand.NotifyCanExecuteChanged();
        ExportSarifCommand.NotifyCanExecuteChanged();
        ExportNavigatorCommand.NotifyCanExecuteChanged();
        ExportDefectDojoCommand.NotifyCanExecuteChanged();
        ExportOcsfCommand.NotifyCanExecuteChanged();
        ExportOscalCommand.NotifyCanExecuteChanged();
        ExportComplianceSummaryCommand.NotifyCanExecuteChanged();
        ExportIntuneCommand.NotifyCanExecuteChanged();
        ExportPdfCommand.NotifyCanExecuteChanged();
    }

    private sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }

    private (IEnumerable<CheckItemViewModel> checks, EnvironmentInfo env) GetExportData()
    {
        var redactor = Export.PrivacyExportSanitizer.CreateRedactor(
            PrivacyMode,
            Environment,
            System.Environment.UserName,
            Environment.ComputerName);
        return (
            Export.PrivacyExportSanitizer.RedactChecks(Checks, redactor),
            Export.PrivacyExportSanitizer.RedactEnvironment(Environment, redactor));
    }

    [RelayCommand]
    private void BrowseExportFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select export folder",
            InitialDirectory = Directory.Exists(ExportOutputFolder) ? ExportOutputFolder : ""
        };

        if (dialog.ShowDialog() == true)
            ExportOutputFolder = dialog.FolderName;
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportSelectedAsync()
    {
        var option = SelectedExportFormat;
        IsExporting = true;
        ScanStatus = $"Exporting {option.DisplayName}...";
        AppendActivity(ScanStatus);
        try
        {
            Directory.CreateDirectory(ExportOutputFolder);
            var baseName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}";

            if (option.IsFolderExport)
            {
                var folder = Path.Combine(ExportOutputFolder, $"{baseName}{option.FileSuffix}");
                var files = Export.SiemContentPackExporter.ExportAll(folder)
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                ScanStatus = $"SIEM content pack exported: {folder} ({files.Length} files)";
                AppendActivity(ScanStatus);
                return;
            }

            var path = Path.Combine(ExportOutputFolder, $"{baseName}{option.FileSuffix}.{option.Extension}");
            await WriteExportAsync(option.Kind, path);
            ScanStatus = $"{option.DisplayName} exported{(PrivacyMode ? " (privacy mode)" : "")}: {path}";
            AppendActivity($"{option.DisplayName} exported");
        }
        catch (Exception ex)
        {
            var logPath = Services.CrashLogWriter.Write(ex, "ExportSelectedAsync");
            ScanStatus = $"Export failed. Crash log: {logPath}";
            AppendActivity($"Export failed: {ex.Message}");
        }
        finally
        {
            IsExporting = false;
        }
    }

    private async Task WriteExportAsync(ExportFormatKind kind, string path)
    {
        var (exportChecks, exportEnv) = GetExportData();

        switch (kind)
        {
            case ExportFormatKind.Html:
                await File.WriteAllTextAsync(path, Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.Pdf:
                await WritePdfExportAsync(path, exportChecks, exportEnv);
                break;
            case ExportFormatKind.Json:
                await File.WriteAllTextAsync(path, Export.JsonExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.Csv:
                await File.WriteAllTextAsync(path, Export.CsvExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.Jsonl:
                await File.WriteAllTextAsync(path, Export.JsonlExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile));
                break;
            case ExportFormatKind.Sarif:
                await File.WriteAllTextAsync(path, Export.SarifExporter.Export(exportChecks, exportEnv));
                break;
            case ExportFormatKind.Navigator:
                await File.WriteAllTextAsync(path, Export.NavigatorExporter.Export(exportChecks));
                break;
            case ExportFormatKind.DefectDojo:
                await File.WriteAllTextAsync(path, Export.DefectDojoExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.Ocsf:
                await File.WriteAllTextAsync(path, Export.OcsfExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile.ToString()));
                break;
            case ExportFormatKind.Oscal:
                await File.WriteAllTextAsync(path, Export.OscalExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.Intune:
                await File.WriteAllTextAsync(path, Export.IntuneExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade));
                break;
            case ExportFormatKind.ComplianceSummary:
                await File.WriteAllTextAsync(path, Export.ComplianceSummaryExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.CmmcHtml:
                await File.WriteAllTextAsync(path, Export.CmmcReportGenerator.ExportHtml(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.CmmcJson:
                await File.WriteAllTextAsync(path, Export.CmmcReportGenerator.ExportJson(exportChecks, exportEnv));
                break;
            default:
                throw new NotSupportedException($"Export format '{kind}' is not supported.");
        }
    }

    private async Task WritePdfExportAsync(string path, IEnumerable<CheckItemViewModel> exportChecks, EnvironmentInfo exportEnv)
    {
        var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade, tier: Models.ReportTier.All);
        var tempHtml = Path.Combine(Path.GetTempPath(), $"nsa_report_{Guid.NewGuid():N}.html");
        try
        {
            await File.WriteAllTextAsync(tempHtml, html);
            var (success, message) = await Export.PdfExporter.ExportAsync(tempHtml, path);
            if (!success)
                throw new InvalidOperationException(message);
        }
        finally
        {
            try { File.Delete(tempHtml); } catch { }
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportHtmlAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "HTML Report|*.html",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.html",
            DefaultExt = ".html"
        };

        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade);
            await File.WriteAllTextAsync(dialog.FileName, html);
            ScanStatus = $"HTML report exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportJsonAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSON Report|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.json",
            DefaultExt = ".json"
        };

        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            var json = Export.JsonExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile, DomainMaturityScore, DomainMaturityGrade);
            await File.WriteAllTextAsync(dialog.FileName, json);
            ScanStatus = $"JSON report exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportCsvAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV|*.csv",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.csv",
            DefaultExt = ".csv"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.CsvExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
            ScanStatus = $"CSV exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportJsonlAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSONL|*.jsonl",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_siem.jsonl",
            DefaultExt = ".jsonl"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.JsonlExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile));
            ScanStatus = $"JSONL exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportSarifAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "SARIF|*.sarif",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.sarif",
            DefaultExt = ".sarif"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.SarifExporter.Export(exportChecks, exportEnv));
            ScanStatus = $"SARIF exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportNavigatorAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "ATT&CK Navigator|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_navigator.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, _) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.NavigatorExporter.Export(exportChecks));
            ScanStatus = $"Navigator layer exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportDefectDojoAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "DefectDojo JSON|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_defectdojo.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.DefectDojoExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
            ScanStatus = $"DefectDojo exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportOcsfAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "OCSF JSONL|*.jsonl",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_ocsf.jsonl",
            DefaultExt = ".jsonl"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.OcsfExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile.ToString()));
            ScanStatus = $"OCSF exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportOscalAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "OSCAL JSON|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_oscal.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.OscalExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
            ScanStatus = $"OSCAL exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportComplianceSummaryAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Compliance Summary JSON|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_summary.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.ComplianceSummaryExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
            ScanStatus = $"Compliance summary exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportIntuneAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Intune JSON|*.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}_intune.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            await File.WriteAllTextAsync(dialog.FileName, Export.IntuneExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade));
            ScanStatus = $"Intune exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportPdfAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF Report|*.pdf",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.pdf",
            DefaultExt = ".pdf"
        };
        if (dialog.ShowDialog() == true)
        {
            var (exportChecks, exportEnv) = GetExportData();
            var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade, tier: Models.ReportTier.All);
            var tempHtml = Path.Combine(Path.GetTempPath(), $"nsa_report_{Guid.NewGuid():N}.html");
            try
            {
                await File.WriteAllTextAsync(tempHtml, html);
                var (success, message) = await Export.PdfExporter.ExportAsync(tempHtml, dialog.FileName);
                ScanStatus = success
                    ? $"PDF exported{(PrivacyMode ? " (privacy mode)" : "")}: {dialog.FileName}"
                    : $"PDF export failed: {message}";
            }
            finally
            {
                try { File.Delete(tempHtml); } catch { }
            }
        }
    }

    [RelayCommand]
    private async Task SaveStateAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Audit State|*.audit.json",
            FileName = $"SecurityAudit_{DateTime.Now:yyyy-MM-dd_HHmm}.audit.json",
            DefaultExt = ".audit.json"
        };

        if (dialog.ShowDialog() == true)
        {
            var state = new AuditState
            {
                Client = Environment.ComputerName,
                Auditor = System.Environment.UserName,
                ScanProfile = SelectedProfile.ToString(),
                Theme = SelectedTheme,
                OverallScore = OverallScore,
                Grade = Grade,
                RansomwareScore = RansomwareScore,
                RansomwareGrade = RansomwareGrade,
                DomainMaturityScore = DomainMaturityScore,
                DomainMaturityGrade = DomainMaturityGrade
            };

            foreach (var check in Checks)
            {
                state.Checks.Add(new CheckState
                {
                    Id = check.Id,
                    Status = check.Status,
                    Findings = check.Findings,
                    Evidence = check.Evidence,
                    Notes = check.Notes,
                    RemediationAssignee = check.RemediationAssignee,
                    RemediationDueDate = check.RemediationDueDate?.ToString("yyyy-MM-dd")
                });
            }

            await File.WriteAllTextAsync(dialog.FileName, state.Serialize());
            ScanStatus = $"State saved: {dialog.FileName}";
        }
    }

    [RelayCommand]
    private async Task LoadStateAsync()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Audit State|*.audit.json|All JSON|*.json",
            DefaultExt = ".audit.json"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var json = await File.ReadAllTextAsync(dialog.FileName);
                var state = AuditState.Deserialize(json);
                if (state is null)
                {
                    ScanStatus = "Failed to load state file.";
                    return;
                }

                var lookup = Checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
                var restored = 0;

                foreach (var cs in state.Checks)
                {
                    if (!lookup.TryGetValue(cs.Id, out var vm)) continue;
                    vm.Status = cs.Status;
                    vm.Findings = cs.Findings;
                    vm.Evidence = cs.Evidence;
                    vm.Notes = cs.Notes;
                    vm.RemediationAssignee = cs.RemediationAssignee;
                    if (DateTime.TryParse(cs.RemediationDueDate, out var due))
                        vm.RemediationDueDate = due;
                    restored++;
                }

                UpdateScoreCounts();
                ScanStatus = $"State loaded: {restored} checks restored from {Path.GetFileName(dialog.FileName)}";
            }
            catch (Exception ex)
            {
                var logPath = Services.CrashLogWriter.Write(ex, "LoadStateAsync");
                ScanStatus = $"Failed to load state file. Crash log: {logPath}";
            }
        }
    }

    private void UpdateScoreCounts()
    {
        PassCount = Checks.Count(c => c.Status == CheckStatus.Pass);
        FailCount = Checks.Count(c => c.Status == CheckStatus.Fail);
        PartialCount = Checks.Count(c => c.Status == CheckStatus.Partial);
        NotApplicableCount = Checks.Count(c => c.Status == CheckStatus.NA);
        NotAssessedCount = Checks.Count(c => c.Status == CheckStatus.NotAssessed);
        NaCount = NotApplicableCount + NotAssessedCount;

        foreach (var summary in CategorySummaries)
        {
            summary.Update(Checks);
        }

        foreach (var summary in CategoryRailItems.Where(s => s.Name.Equals("All", StringComparison.OrdinalIgnoreCase)))
        {
            summary.Update(Checks);
        }

        var (score, _) = RiskScoreEngine.Calculate(Checks);
        OverallScore = score;

        var (rwScore, rwGrade) = RansomwareReadinessEngine.Calculate(Checks);
        RansomwareScore = rwScore;
        RansomwareGrade = rwGrade;

        var (dmScore, dmGrade, _) = DomainMaturityEngine.Calculate(Checks);
        DomainMaturityScore = dmScore;
        DomainMaturityGrade = dmGrade;

        OnPropertyChanged(nameof(HasAssessedChecks));
        OnPropertyChanged(nameof(ScoreSubtitle));
        OnPropertyChanged(nameof(ScanReadinessText));
        OnPropertyChanged(nameof(ExportAvailabilityText));
        OnPropertyChanged(nameof(Grade));
        OnPropertyChanged(nameof(GradeBrushKey));
        OnPropertyChanged(nameof(OverallScoreDisplay));
        OnPropertyChanged(nameof(AssessedCount));
        OnPropertyChanged(nameof(AssessedChecksDisplay));
        OnPropertyChanged(nameof(OutcomeSummaryDisplay));
        OnPropertyChanged(nameof(RiskPostureLabel));
        NotifyExportCommandCanExecuteChanged();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SelectedCategory = "All";
        SearchText = "";
        StatusFilter = "All";
        RefreshFilteredChecks(preserveSelection: true);
    }

    private void RefreshFilteredChecks(bool preserveSelection = false)
    {
        FilteredChecks.Refresh();
        var visibleChecks = FilteredChecks.Cast<CheckItemViewModel>().ToList();
        VisibleCheckCount = visibleChecks.Count;
        if (!preserveSelection || SelectedCheck is null || !visibleChecks.Contains(SelectedCheck))
        {
            SelectedCheck = visibleChecks.FirstOrDefault();
        }
    }

    private void AppendActivity(string message)
    {
        ActivityLog.Add($"{DateTime.Now:HH:mm:ss}  {message}");
        while (ActivityLog.Count > 80)
        {
            ActivityLog.RemoveAt(0);
        }
    }
}

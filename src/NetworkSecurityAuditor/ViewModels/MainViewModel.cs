using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Localization;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private static readonly ExportFormatOption[] DefaultExportFormats =
    [
        new(ExportFormatKind.Html, UiText.ExportHtmlReport, "", "html"),
        new(ExportFormatKind.Pdf, UiText.ExportPdfReport, "", "pdf"),
        new(ExportFormatKind.Json, UiText.ExportFindingsJson, "", "json"),
        new(ExportFormatKind.Csv, UiText.ExportFindingsCsv, "", "csv"),
        new(ExportFormatKind.Jsonl, UiText.ExportSiemJsonl, "_siem", "jsonl"),
        new(ExportFormatKind.Sarif, UiText.ExportSarif, "", "sarif"),
        new(ExportFormatKind.Navigator, UiText.ExportAttackNavigator, "_navigator", "json"),
        new(ExportFormatKind.DefectDojo, UiText.ExportDefectDojoJson, "_defectdojo", "json"),
        new(ExportFormatKind.Ocsf, UiText.ExportOcsfJsonl, "_ocsf", "jsonl"),
        new(ExportFormatKind.Oscal, UiText.ExportOscalJson, "_oscal", "json"),
        new(ExportFormatKind.OscalPoam, UiText.ExportOscalPoamJson, "_oscal_poam", "json"),
        new(ExportFormatKind.Intune, UiText.ExportIntuneJson, "_intune", "json"),
        new(ExportFormatKind.ComplianceSummary, UiText.ExportComplianceSummaryJson, "_summary", "json"),
        new(ExportFormatKind.SiemContentPack, UiText.ExportSiemContentPack, "_siem_pack", "", IsFolderExport: true),
        new(ExportFormatKind.CmmcHtml, UiText.ExportCmmcHtml, "_cmmc", "html"),
        new(ExportFormatKind.CmmcJson, UiText.ExportCmmcJson, "_cmmc", "json")
    ];

    private static readonly string DefaultExportOutputFolder = Path.Combine(
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.MyDocuments),
        "NetworkSecurityAuditor");

    private CancellationTokenSource? _scanCts;
    private TaskCompletionSource? _scanCompletion;
    private int _shutdownRequested;
    private readonly RunChecksAsync _runChecksAsync;
    private readonly OpenReportFile _openReportFile;

    internal delegate Task<Dictionary<string, CheckResult>> RunChecksAsync(
        EnvironmentInfo env,
        AuditOptions options,
        IProgress<(string checkId, CheckResult result)>? progress,
        CancellationToken ct,
        IProgress<(string checkId, int index, int total)>? startedProgress);

    internal delegate void OpenReportFile(string path);

    internal bool IsShutdownRequested => Volatile.Read(ref _shutdownRequested) != 0;

    public ObservableCollection<CheckItemViewModel> Checks { get; } = [];

    public ObservableCollection<CategorySummaryViewModel> CategorySummaries { get; } = [];

    public ObservableCollection<CategorySummaryViewModel> CategoryRailItems { get; } = [];

    public ObservableCollection<string> ActivityLog { get; } = [];

    public ICollectionView FilteredChecks { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _selectedCategory = UiText.FilterAll;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(IsSearchWatermarkVisible), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _searchText = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilters), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private string _statusFilter = UiText.FilterAll;

    [ObservableProperty]
    private CheckItemViewModel? _selectedCheck;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopScanCommand))]
    [NotifyCanExecuteChangedFor(nameof(SaveStateCommand))]
    [NotifyCanExecuteChangedFor(nameof(LoadStateCommand))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ExportAvailabilityText), nameof(ScanProgressDisplay), nameof(ScanStatusHeadline), nameof(ScanProgressBrushKey))]
    [NotifyPropertyChangedFor(nameof(CanEditScanOptions), nameof(StartScanHelpText), nameof(StopScanHelpText), nameof(ScanProfileHelpText), nameof(SaveStateHelpText), nameof(LoadStateHelpText), nameof(StatePersistenceText), nameof(StatePersistenceBrushKey))]
    private bool _isScanning;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveStateCommand))]
    [NotifyCanExecuteChangedFor(nameof(LoadStateCommand))]
    [NotifyPropertyChangedFor(nameof(ScanReadinessText), nameof(ExportAvailabilityText), nameof(ScanStatusHeadline))]
    [NotifyPropertyChangedFor(nameof(SaveStateHelpText), nameof(LoadStateHelpText), nameof(StatePersistenceText), nameof(StatePersistenceBrushKey))]
    private bool _isExporting;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    [NotifyPropertyChangedFor(nameof(ReadinessDisplay), nameof(ReadinessBrushKey), nameof(ScanReadinessText), nameof(StartScanHelpText))]
    private bool _isEnvironmentReady;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private string _scanStatus = UiText.Ready;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScanProgressDisplay), nameof(ScanStatusHeadline), nameof(ScanProgressBrushKey))]
    private double _scanProgressPercent;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProfileSummary), nameof(StartScanHelpText), nameof(ScanProfileHelpText))]
    private ScanProfileType _selectedProfile = ScanProfileType.Full;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatePersistenceText), nameof(StatePersistenceBrushKey))]
    private bool _hasUnsavedChanges;

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
    [NotifyPropertyChangedFor(nameof(RansomwareScoreDisplay), nameof(RansomwareGradeDisplay), nameof(RansomwareBrushKey))]
    private int _ransomwareScore;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RansomwareGradeDisplay), nameof(RansomwareBrushKey))]
    private string _ransomwareGrade = "N/A";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DomainMaturityScoreDisplay), nameof(DomainMaturityGradeDisplay), nameof(DomainMaturityBrushKey))]
    private int _domainMaturityScore;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DomainMaturityGradeDisplay), nameof(DomainMaturityBrushKey))]
    private string _domainMaturityGrade = "N/A";

    public string[] Categories { get; private set; } = [UiText.FilterAll];

    public string[] StatusFilters { get; } =
        [UiText.FilterAll, UiText.StatusPass, UiText.StatusPartial, UiText.StatusFail, UiText.StatusNotApplicable, UiText.FilterNotAssessed];

    public string[] AvailableThemes { get; } = ["Catppuccin Mocha"];

    public ScanProfileType[] AvailableProfiles { get; } = Enum
        .GetValues<ScanProfileType>()
        .Where(profile => profile != ScanProfileType.Cloud)
        .ToArray();

    public IReadOnlyList<ExportFormatOption> ExportFormats { get; } = DefaultExportFormats;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExportAvailabilityText))]
    private ExportFormatOption _selectedExportFormat = DefaultExportFormats[0];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExportAvailabilityText))]
    private string _exportOutputFolder = DefaultExportOutputFolder;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasVisibleChecks), nameof(HasNoVisibleChecks), nameof(VisibleChecksDisplay), nameof(FilterEmptyStateTitle), nameof(FilterEmptyStateDetail))]
    private int _visibleCheckCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ReadinessDisplay), nameof(ReadinessBrushKey))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private int _preflightPassedCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ReadinessDisplay), nameof(ReadinessBrushKey))]
    [NotifyPropertyChangedFor(nameof(ScoreSubtitle), nameof(ScanReadinessText), nameof(ScanStatusHeadline))]
    private int _preflightTotalCount;

    public MainViewModel() : this(DefaultRunChecksAsync)
    {
    }

    internal MainViewModel(RunChecksAsync runChecksAsync, OpenReportFile? openReportFile = null)
    {
        _runChecksAsync = runChecksAsync;
        _openReportFile = openReportFile ?? OpenReportWithShell;
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

        if (SelectedCategory != UiText.FilterAll && check.Category != SelectedCategory)
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
            var value when value == UiText.StatusPass => check.Status == CheckStatus.Pass,
            var value when value == UiText.StatusPartial => check.Status == CheckStatus.Partial,
            var value when value == UiText.StatusFail => check.Status == CheckStatus.Fail,
            var value when value == UiText.StatusNotApplicable => check.Status == CheckStatus.NA,
            var value when value == UiText.FilterNotAssessed => check.Status == CheckStatus.NotAssessed,
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

    partial void OnSelectedProfileChanged(ScanProfileType value)
    {
        HasUnsavedChanges = true;
    }

    partial void OnSelectedThemeChanged(string value)
    {
        HasUnsavedChanges = true;
    }

    internal void RefreshThemeResources()
    {
        OnPropertyChanged(nameof(StatePersistenceBrushKey));
        OnPropertyChanged(nameof(ReadinessBrushKey));
        OnPropertyChanged(nameof(RansomwareBrushKey));
        OnPropertyChanged(nameof(DomainMaturityBrushKey));
        OnPropertyChanged(nameof(ScanProgressBrushKey));
        OnPropertyChanged(nameof(GradeBrushKey));

        foreach (var check in Checks)
            check.RefreshThemeResources();
        foreach (var summary in CategoryRailItems)
            summary.RefreshThemeResources();
    }

    public bool HasAssessedChecks => Checks.Any(c => c.Status is CheckStatus.Pass or CheckStatus.Partial or CheckStatus.Fail);

    public bool HasVisibleChecks => VisibleCheckCount > 0;

    public bool HasNoVisibleChecks => !HasVisibleChecks;

    public bool HasActiveFilters =>
        SelectedCategory != UiText.FilterAll ||
        StatusFilter != UiText.FilterAll ||
        !string.IsNullOrWhiteSpace(SearchText);

    public bool IsSearchWatermarkVisible => string.IsNullOrWhiteSpace(SearchText);

    public string VisibleChecksDisplay => Checks.Count == 0
        ? UiText.NoChecksLoaded
        : UiText.Format(nameof(UiText.VisibleChecksFormat), VisibleCheckCount, Checks.Count);

    public string FilterEmptyStateTitle => Checks.Count == 0
        ? UiText.NoChecksLoaded
        : UiText.NoChecksMatch;

    public string FilterEmptyStateDetail => HasActiveFilters
        ? UiText.ClearFiltersDetail
        : UiText.LoadCatalogDetail;

    public string Grade => HasAssessedChecks ? RiskScoreEngine.GradeFromScore(OverallScore) : "\u2014";

    public string OverallScoreDisplay => HasAssessedChecks ? $"{OverallScore}/100" : UiText.NotScanned;

    public string ScoreSubtitle
    {
        get
        {
            if (IsScanning)
                return ScanStatus;

            if (HasAssessedChecks)
                return UiText.Format(
                    nameof(UiText.AssessedOpenFormat), PassCount + PartialCount + FailCount, NotAssessedCount);

            return PreflightTotalCount > 0
                ? UiText.Format(nameof(UiText.PreflightPassedFormat), PreflightPassedCount, PreflightTotalCount)
                : UiText.ReadyForPreflight;
        }
    }

    public int AssessedCount => PassCount + PartialCount + FailCount;

    public string AssessedChecksDisplay => Checks.Count == 0
        ? "0 / 0"
        : $"{AssessedCount} / {Checks.Count}";

    public string OutcomeSummaryDisplay => UiText.Format(
        nameof(UiText.OutcomeSummaryFormat), PassCount, PartialCount, FailCount);

    public string ProfileSummary => UiText.Format(nameof(UiText.ProfileSummaryFormat), SelectedProfile);

    public bool CanEditScanOptions => !IsScanning;

    public string StartScanHelpText => IsScanning
        ? UiText.ScanAlreadyRunning
        : !IsEnvironmentReady
            ? UiText.EnvironmentStillRunning
            : UiText.Format(nameof(UiText.RunProfileHelpFormat), SelectedProfile);

    public string StopScanHelpText => IsScanning
        ? UiText.CancelRunningScan
        : UiText.NoScanRunning;

    public string ScanProfileHelpText => IsScanning
        ? UiText.ProfileLocked
        : UiText.Format(nameof(UiText.ChooseProfileFormat), SelectedProfile);

    public string PrivacyModeHelpText => UiText.PrivacyModeHelp;

    public string SaveStateHelpText => IsScanning
        ? UiText.SaveUnavailableScanning
        : IsExporting
            ? UiText.SaveUnavailableExporting
            : UiText.SaveStateHelp;

    public string LoadStateHelpText => IsScanning
        ? UiText.LoadUnavailableScanning
        : IsExporting
            ? UiText.LoadUnavailableExporting
            : UiText.LoadStateHelp;

    public string StatePersistenceText => IsScanning
        ? UiText.AssessmentChanging
        : IsExporting
            ? UiText.ExportInProgress
            : HasUnsavedChanges
                ? UiText.UnsavedChanges
                : UiText.NoUnsavedChanges;

    public string StatePersistenceBrushKey => IsScanning || IsExporting
        ? "InfoAccent"
        : HasUnsavedChanges
            ? "ProgressMid"
            : "StatusNeutral";

    public string ReadinessDisplay => !IsEnvironmentReady
        ? UiText.DetectingEnvironment
        : PreflightTotalCount > 0
            ? UiText.Format(nameof(UiText.ReadyCountFormat), PreflightPassedCount, PreflightTotalCount)
            : UiText.PreflightPending;

    public string ReadinessBrushKey
    {
        get
        {
            if (!IsEnvironmentReady || PreflightTotalCount == 0)
                return "StatusNeutral";

            if (PreflightPassedCount == PreflightTotalCount)
                return "ProgressGood";

            return PreflightPassedCount > 0 ? "ProgressMid" : "ProgressBad";
        }
    }

    public string RansomwareGradeDisplay => HasAssessedChecks ? RansomwareGrade : "\u2014";

    public string RansomwareScoreDisplay => HasAssessedChecks ? $"{RansomwareScore}/100" : UiText.Pending;

    public string RansomwareBrushKey => HasAssessedChecks ? GradeBrushFor(RansomwareGrade) : "StatusNeutral";

    public string DomainMaturityGradeDisplay => HasAssessedChecks ? DomainMaturityGrade : "\u2014";

    public string DomainMaturityScoreDisplay => HasAssessedChecks ? $"{DomainMaturityScore}/100" : UiText.Pending;

    public string DomainMaturityBrushKey => HasAssessedChecks ? GradeBrushFor(DomainMaturityGrade) : "StatusNeutral";

    public string ScanProgressDisplay => IsScanning || ScanProgressPercent > 0
        ? $"{ScanProgressPercent:0}%"
        : UiText.Idle;

    public string ScanProgressBrushKey => IsScanning || ScanProgressPercent > 0
        ? "Accent"
        : "StatusNeutral";

    public string ScanStatusHeadline
    {
        get
        {
            if (IsScanning)
                return ScanProgressPercent > 0
                    ? UiText.Format(nameof(UiText.ScanningPercentFormat), ScanProgressPercent)
                    : UiText.ScanningStatus;

            if (IsExporting)
                return UiText.ExportingReport;

            if (StartsWithResourceFormat(ScanStatus, nameof(UiText.PreflightCompleteFormat)))
                return UiText.Ready;

            if (ScanStatus.Contains(" exported", StringComparison.OrdinalIgnoreCase))
                return UiText.ExportComplete;

            if (StartsWithResourceFormat(ScanStatus, nameof(UiText.StateLoadedFormat)))
                return UiText.StateLoaded;

            if (StartsWithResourceFormat(ScanStatus, nameof(UiText.StateSavedFormat)))
                return UiText.StateSaved;

            return CompactStatus(ScanStatus, 30);
        }
    }

    public string RiskPostureLabel
    {
        get
        {
            if (!HasAssessedChecks)
                return UiText.AwaitingAssessment;

            return Grade switch
            {
                "A" => UiText.StrongPosture,
                "B" => UiText.ManagedRisk,
                "C" => UiText.ModerateRisk,
                "D" => UiText.HighRisk,
                "F" => UiText.CriticalRisk,
                _ => UiText.Unknown
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
                return UiText.Format(nameof(UiText.ExportingFormat), SelectedExportFormat.DisplayName);

            if (!IsEnvironmentReady)
                return UiText.PreparingWorkspace;

            if (HasAssessedChecks)
                return UiText.Format(
                    nameof(UiText.AssessedExportReadyFormat), PassCount + PartialCount + FailCount);

            if (PreflightTotalCount == 0)
                return UiText.ReadyLocalChecks;

            var advisories = PreflightTotalCount - PreflightPassedCount;
            return advisories == 0
                ? UiText.ReadyToScan
                : UiText.Format(nameof(UiText.ReadyWithAdvisoriesFormat), advisories);
        }
    }

    private static string CompactStatus(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
            return string.IsNullOrWhiteSpace(value) ? UiText.Ready : value;

        return value[..Math.Max(0, maxLength - 3)].TrimEnd() + "...";
    }

    private static bool StartsWithResourceFormat(string value, string key)
    {
        var format = UiText.Get(key);
        var placeholder = format.IndexOf('{');
        var prefix = placeholder >= 0 ? format[..placeholder] : format;
        return value.StartsWith(prefix, StringComparison.CurrentCultureIgnoreCase);
    }

    public string ExportAvailabilityText
    {
        get
        {
            if (IsScanning)
                return UiText.ExportPaused;

            if (IsExporting)
                return UiText.Format(nameof(UiText.ExportingFormat), SelectedExportFormat.DisplayName);

            if (string.IsNullOrWhiteSpace(ExportOutputFolder))
                return UiText.ChooseExportFolder;

            return HasAssessedChecks
                ? UiText.Format(nameof(UiText.ReadyToExportFormat), SelectedExportFormat.DisplayName)
                : UiText.RunBeforeExport;
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

    private static string GradeBrushFor(string grade) => grade switch
    {
        "A" => "ProgressGood",
        "B" => "GradeB",
        "C" => "ProgressMid",
        "D" => "SeverityHigh",
        "F" => "ProgressBad",
        _ => "StatusNeutral"
    };

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
        ? UiText.DomainJoined
        : Environment.JoinType;

    [ObservableProperty]
    private string _preflightSummary = "";

    public void RunPreflight()
    {
        var results = Services.PreflightChecker.Run(Environment);
        var passed = results.Count(r => r.Passed);
        var lines = results.Select(r => UiText.Format(
            nameof(UiText.PreflightResultFormat),
            r.Passed ? UiText.PreflightPassTag : UiText.PreflightWarningTag,
            r.Name,
            r.Detail));
        PreflightPassedCount = passed;
        PreflightTotalCount = results.Count;
        PreflightSummary = UiText.Format(
            nameof(UiText.PreflightSummaryFormat), passed, results.Count, string.Join("\n", lines));
        ScanStatus = UiText.Format(nameof(UiText.PreflightCompleteFormat), passed, results.Count);
        AppendActivity(ScanStatus);
        foreach (var line in lines)
        {
            AppendActivity(line);
        }
        IsEnvironmentReady = true;
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

        Categories = [UiText.FilterAll, .. CheckCatalog.Categories];
        OnPropertyChanged(nameof(Categories));
        CategoryRailItems.Add(new CategorySummaryViewModel { Name = UiText.FilterAll });
        foreach (var category in CheckCatalog.Categories)
        {
            var summary = new CategorySummaryViewModel { Name = category };
            CategorySummaries.Add(summary);
            CategoryRailItems.Add(summary);
        }

        SelectedCheck = Checks.FirstOrDefault();
        RefreshFilteredChecks(preserveSelection: true);
        UpdateScoreCounts();
        HasUnsavedChanges = false;
        AppendActivity(UiText.Format(
            nameof(UiText.CatalogLoadedFormat), Checks.Count, CategorySummaries.Count));
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
        if (e.PropertyName is nameof(CheckItemViewModel.Status)
            or nameof(CheckItemViewModel.Findings)
            or nameof(CheckItemViewModel.Evidence)
            or nameof(CheckItemViewModel.Notes)
            or nameof(CheckItemViewModel.RemediationAssignee)
            or nameof(CheckItemViewModel.RemediationDueDate))
        {
            HasUnsavedChanges = true;
        }

        if (e.PropertyName != nameof(CheckItemViewModel.Status)) return;

        UpdateScoreCounts();
        RefreshFilteredChecks(preserveSelection: true);
    }

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        if (IsScanning || IsShutdownRequested) return;

        var scanCts = new CancellationTokenSource();
        var scanCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _scanCts = scanCts;
        _scanCompletion = scanCompletion;
        IsScanning = true;
        ScanStatus = UiText.Scanning;
        ScanProgressPercent = 0;
        AppendActivity(UiText.Format(nameof(UiText.ScanStartedFormat), SelectedProfile));

        var options = new AuditOptions
        {
            ScanProfile = SelectedProfile
        };

        var completed = 0;
        var runningTotal = 0;
        var checkLookup = Checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var unsupportedProfile = false;
        var noApplicableChecks = false;
        var scanFailed = false;

        var startedProgress = new InlineProgress<(string checkId, int index, int total)>(update =>
        {
            if (IsShutdownRequested) return;
            runningTotal = update.total;
            SetRunningCheck(update.checkId);
            ScanProgressPercent = update.total > 0
                ? (double)(update.index - 1) / update.total * 100
                : 0;

            if (checkLookup.TryGetValue(update.checkId, out var vm))
            {
                vm.IsRunning = true;
                ScanStatus = UiText.Format(
                    nameof(UiText.RunningCheckFormat), update.checkId, vm.Label, update.index, update.total);
                AppendActivity(UiText.Format(
                    nameof(UiText.RunningCheckActivityFormat), update.checkId, vm.Label));
            }
            else
            {
                ScanStatus = UiText.Format(
                    nameof(UiText.RunningCheckCompactFormat), update.checkId, update.index, update.total);
                AppendActivity(UiText.Format(
                    nameof(UiText.RunningCheckActivityCompactFormat), update.checkId));
            }
        });

        var progress = new InlineProgress<(string checkId, CheckResult result)>(update =>
        {
            if (IsShutdownRequested) return;
            var nextCompleted = completed + 1;
            if (checkLookup.TryGetValue(update.checkId, out var vm))
            {
                vm.Status = update.result.Status;
                vm.Findings = update.result.Findings;
                vm.Evidence = update.result.Evidence;
                vm.DurationMs = update.result.Duration.TotalMilliseconds;
                vm.IsRunning = false;
                ScanStatus = UiText.Format(
                    nameof(UiText.CompletedCheckFormat), update.checkId, vm.Label, nextCompleted, runningTotal);
                AppendActivity(UiText.Format(
                    nameof(UiText.CompletedCheckActivityFormat), update.checkId, update.result.Status));
            }
            else
            {
                ScanStatus = UiText.Format(
                    nameof(UiText.CompletedCheckCompactFormat), update.checkId, nextCompleted, runningTotal);
                AppendActivity(UiText.Format(
                    nameof(UiText.CompletedCheckActivityFormat), update.checkId, update.result.Status));
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
            if (profileIds.Length == 0)
            {
                unsupportedProfile = true;
                ScanStatus = UiText.Format(nameof(UiText.UnsupportedProfileFormat), options.ScanProfile);
                AppendActivity(ScanStatus);
                ScanProgressPercent = 0;
                return;
            }

            var applicableIds = CheckRunner.ResolveApplicableCheckIds(Environment, options);
            runningTotal = applicableIds.Length;
            if (applicableIds.Length == 0)
            {
                noApplicableChecks = true;
                ScanStatus = UiText.Format(nameof(UiText.NoApplicableChecksFormat), options.ScanProfile);
                AppendActivity(ScanStatus);
                ScanProgressPercent = 0;
                return;
            }

            var results = await _runChecksAsync(Environment, options, progress, scanCts.Token, startedProgress);
            completed = results.Count;
        }
        catch (OperationCanceledException)
        {
            // User cancelled
        }
        catch (Exception ex)
        {
            if (!IsShutdownRequested)
            {
                scanFailed = true;
                var logPath = Services.CrashLogWriter.Write(ex, "StartScanAsync");
                ScanStatus = UiText.Format(nameof(UiText.ScanFailedFormat), logPath);
                AppendActivity(UiText.Format(nameof(UiText.ScanFailedActivityFormat), ex.Message));
                AppendActivity(UiText.Format(nameof(UiText.CrashLogFormat), logPath));
            }
        }
        finally
        {
            if (!IsShutdownRequested)
            {
                ClearRunningChecks();
                IsScanning = false;
                var total = runningTotal;
                if (!unsupportedProfile && !noApplicableChecks && !scanFailed)
                {
                    var scanWasCancelled = scanCts.Token.IsCancellationRequested;
                    ScanStatus = scanWasCancelled
                        ? UiText.Format(nameof(UiText.ScanCancelledFormat), completed, total)
                        : UiText.Format(nameof(UiText.ScanCompleteFormat), completed, total);
                    AppendActivity(ScanStatus);
                    if (!scanWasCancelled && total > 0)
                    {
                        ScanProgressPercent = 100;
                        await GenerateAndOpenHtmlReportAsync();
                    }
                }
            }
            else
            {
                IsScanning = false;
            }

            scanCts.Dispose();
            if (ReferenceEquals(_scanCts, scanCts)) _scanCts = null;
            scanCompletion.TrySetResult();
            if (ReferenceEquals(_scanCompletion, scanCompletion)) _scanCompletion = null;

            StartScanCommand.NotifyCanExecuteChanged();
            StopScanCommand.NotifyCanExecuteChanged();
        }
    }

    private async Task GenerateAndOpenHtmlReportAsync()
    {
        var outputFolder = string.IsNullOrWhiteSpace(ExportOutputFolder)
            ? DefaultExportOutputFolder
            : ExportOutputFolder;

        IsExporting = true;
        ScanStatus = UiText.GeneratingHtmlReport;
        AppendActivity(ScanStatus);

        try
        {
            Directory.CreateDirectory(outputFolder);
            var reportPath = Path.Combine(
                outputFolder,
                $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.html");

            await WriteExportAsync(ExportFormatKind.Html, reportPath);
            _openReportFile(reportPath);

            ScanStatus = UiText.Format(nameof(UiText.ReportGeneratedAndOpenedFormat), reportPath);
            AppendActivity(UiText.HtmlReportGeneratedAndOpened);
        }
        catch (Exception ex)
        {
            var logPath = Services.CrashLogWriter.Write(ex, "GenerateAndOpenHtmlReportAsync");
            ScanStatus = UiText.Format(nameof(UiText.ReportGenerationFailedFormat), logPath);
            AppendActivity(UiText.Format(nameof(UiText.ReportOpenFailedFormat), ex.Message));
        }
        finally
        {
            IsExporting = false;
        }
    }

    private bool CanStartScan() => !IsScanning && !IsShutdownRequested && IsEnvironmentReady;

    internal async Task ShutdownAsync(TimeSpan? cleanupTimeout = null)
    {
        if (Interlocked.Exchange(ref _shutdownRequested, 1) != 0)
            return;

        try { _scanCts?.Cancel(); } catch (ObjectDisposedException) { }

        var completion = _scanCompletion?.Task;
        if (completion is null)
            return;

        var timeout = cleanupTimeout ?? TimeSpan.FromSeconds(5);
        await Task.WhenAny(completion, Task.Delay(timeout));
    }

    [RelayCommand(CanExecute = nameof(CanStopScan))]
    private void StopScan()
    {
        _scanCts?.Cancel();
        ScanStatus = UiText.Cancelling;
        AppendActivity(UiText.ScanCancellationRequested);
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

    internal async Task RunGuardedWriteAsync(string operation, Func<Task> write)
    {
        if (IsScanning || IsExporting)
            return;

        IsExporting = true;
        ScanStatus = UiText.Format(nameof(UiText.OperationProgressFormat), operation);
        AppendActivity(ScanStatus);
        try
        {
            await write();
        }
        catch (Exception ex)
        {
            var logPath = Services.CrashLogWriter.Write(ex, operation);
            ScanStatus = UiText.Format(nameof(UiText.OperationFailedFormat), operation, logPath);
            AppendActivity(UiText.Format(nameof(UiText.OperationFailedActivityFormat), operation, ex.Message));
        }
        finally
        {
            IsExporting = false;
        }
    }

    private void SetExportSucceeded(string displayName, string path)
    {
        ScanStatus = UiText.Format(
            nameof(UiText.ExportSucceededFormat),
            displayName,
            PrivacyMode ? UiText.PrivacyModeSuffix : string.Empty,
            path);
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
            Title = UiText.SelectExportFolder,
            InitialDirectory = Directory.Exists(ExportOutputFolder) ? ExportOutputFolder : ""
        };

        if (dialog.ShowDialog() == true)
            ExportOutputFolder = dialog.FolderName;
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportSelectedAsync()
    {
        var option = SelectedExportFormat;
        await RunGuardedWriteAsync(
            UiText.Format(nameof(UiText.ExportingOperationFormat), option.DisplayName),
            async () =>
        {
            Directory.CreateDirectory(ExportOutputFolder);
            var baseName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}";

            if (option.IsFolderExport)
            {
                var folder = Path.Combine(ExportOutputFolder, $"{baseName}{option.FileSuffix}");
                var files = Export.SiemContentPackExporter.ExportAll(folder)
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                await Export.DataHandlingManifestWriter.WriteAsync(
                    Path.Combine(folder, "data-handling.json"),
                    PrivacyMode,
                    files);
                ScanStatus = UiText.Format(nameof(UiText.SiemPackExportedFormat), folder, files.Length);
                AppendActivity(ScanStatus);
                return;
            }

            var path = Path.Combine(ExportOutputFolder, $"{baseName}{option.FileSuffix}.{option.Extension}");
            await WriteExportAsync(option.Kind, path);
            await Export.DataHandlingManifestWriter.WriteAsync(
                Export.DataHandlingManifestWriter.SidecarPath(path),
                PrivacyMode,
                [path]);
            SetExportSucceeded(option.DisplayName, path);
            AppendActivity(UiText.Format(nameof(UiText.ExportActivityFormat), option.DisplayName));
        });
    }

    private async Task WriteExportAsync(ExportFormatKind kind, string path)
    {
        var (exportChecks, exportEnv) = GetExportData();

        switch (kind)
        {
            case ExportFormatKind.Html:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.Pdf:
                await WritePdfExportAsync(path, exportChecks, exportEnv);
                break;
            case ExportFormatKind.Json:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.JsonExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.Csv:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.CsvExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.Jsonl:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.JsonlExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile));
                break;
            case ExportFormatKind.Sarif:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.SarifExporter.Export(exportChecks, exportEnv));
                break;
            case ExportFormatKind.Navigator:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.NavigatorExporter.Export(exportChecks));
                break;
            case ExportFormatKind.DefectDojo:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.DefectDojoExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.Ocsf:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.OcsfExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile.ToString()));
                break;
            case ExportFormatKind.Oscal:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.OscalExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.OscalPoam:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.OscalPoamExporter.Export(exportChecks, exportEnv));
                break;
            case ExportFormatKind.Intune:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.IntuneExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade));
                break;
            case ExportFormatKind.ComplianceSummary:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.ComplianceSummaryExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
                break;
            case ExportFormatKind.CmmcHtml:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.CmmcReportGenerator.ExportHtml(exportChecks, exportEnv, OverallScore, Grade));
                break;
            case ExportFormatKind.CmmcJson:
                await AtomicFileWriter.WriteAllTextAsync(path, Export.CmmcReportGenerator.ExportJson(exportChecks, exportEnv));
                break;
            default:
                throw new NotSupportedException(UiText.Format(nameof(UiText.UnsupportedExportFormat), kind));
        }
    }

    private static void OpenReportWithShell(string path)
    {
        var psi = new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        };
        Process.Start(psi);
    }

    private async Task WritePdfExportAsync(string path, IEnumerable<CheckItemViewModel> exportChecks, EnvironmentInfo exportEnv)
    {
        var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade, tier: Models.ReportTier.All);
        var tempHtml = Path.Combine(Path.GetTempPath(), $"nsa_report_{Guid.NewGuid():N}.html");
        try
        {
            await AtomicFileWriter.WriteAllTextAsync(tempHtml, html);
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
            Filter = $"{UiText.ExportHtmlReport}|*.html",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.html",
            DefaultExt = ".html"
        };

        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportHtmlReport, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade);
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, html);
                SetExportSucceeded(UiText.ExportHtmlReport, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportJsonAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportFindingsJson}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.json",
            DefaultExt = ".json"
        };

        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportFindingsJson, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                var json = Export.JsonExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile, DomainMaturityScore, DomainMaturityGrade);
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, json);
                SetExportSucceeded(UiText.ExportFindingsJson, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportCsvAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportFindingsCsv}|*.csv",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.csv",
            DefaultExt = ".csv"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportFindingsCsv, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.CsvExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                SetExportSucceeded(UiText.ExportFindingsCsv, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportJsonlAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportSiemJsonl}|*.jsonl",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_siem.jsonl",
            DefaultExt = ".jsonl"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportSiemJsonl, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.JsonlExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile));
                SetExportSucceeded(UiText.ExportSiemJsonl, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportSarifAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportSarif}|*.sarif",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.sarif",
            DefaultExt = ".sarif"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportSarif, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.SarifExporter.Export(exportChecks, exportEnv));
                SetExportSucceeded(UiText.ExportSarif, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportNavigatorAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportAttackNavigator}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_navigator.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportAttackNavigator, async () =>
            {
                var (exportChecks, _) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.NavigatorExporter.Export(exportChecks));
                SetExportSucceeded(UiText.ExportAttackNavigator, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportDefectDojoAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportDefectDojoJson}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_defectdojo.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportDefectDojoJson, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.DefectDojoExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                SetExportSucceeded(UiText.ExportDefectDojoJson, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportOcsfAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportOcsfJsonl}|*.jsonl",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_ocsf.jsonl",
            DefaultExt = ".jsonl"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportOcsfJsonl, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.OcsfExporter.Export(exportChecks, exportEnv, OverallScore, Grade, SelectedProfile.ToString()));
                SetExportSucceeded(UiText.ExportOcsfJsonl, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportOscalAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportOscalJson}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_oscal.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportOscalJson, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.OscalExporter.Export(exportChecks, exportEnv, OverallScore, Grade));
                SetExportSucceeded(UiText.ExportOscalJson, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportComplianceSummaryAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportComplianceSummaryJson}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_summary.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportComplianceSummaryJson, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.ComplianceSummaryExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade));
                SetExportSucceeded(UiText.ExportComplianceSummaryJson, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportIntuneAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportIntuneJson}|*.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}_intune.json",
            DefaultExt = ".json"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportIntuneJson, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, Export.IntuneExporter.Export(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade));
                SetExportSucceeded(UiText.ExportIntuneJson, dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanExport))]
    private async Task ExportPdfAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportPdfReport}|*.pdf",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.pdf",
            DefaultExt = ".pdf"
        };
        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.ExportPdfReport, async () =>
            {
                var (exportChecks, exportEnv) = GetExportData();
                var html = Export.HtmlReportGenerator.Generate(exportChecks, exportEnv, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade, tier: Models.ReportTier.All);
                var tempHtml = Path.Combine(Path.GetTempPath(), $"nsa_report_{Guid.NewGuid():N}.html");
                try
                {
                    await AtomicFileWriter.WriteAllTextAsync(tempHtml, html);
                    var (success, message) = await Export.PdfExporter.ExportAsync(tempHtml, dialog.FileName);
                    if (!success) throw new InvalidOperationException(message);
                    SetExportSucceeded(UiText.ExportPdfReport, dialog.FileName);
                }
                finally
                {
                    try { File.Delete(tempHtml); } catch { }
                }
            });
    }

    [RelayCommand(CanExecute = nameof(CanManageState))]
    private async Task SaveStateAsync()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = $"{UiText.ExportAuditState}|*.audit.json",
            FileName = $"SecurityAudit_{DateTime.Now.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture)}.audit.json",
            DefaultExt = ".audit.json"
        };

        if (dialog.ShowDialog() == true)
            await RunGuardedWriteAsync(UiText.OperationSavingAuditState, async () =>
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
                        RemediationDueDate = check.RemediationDueDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
                    });
                }

                await AtomicFileWriter.WriteAllTextAsync(dialog.FileName, state.Serialize());
                HasUnsavedChanges = false;
                ScanStatus = UiText.Format(nameof(UiText.StateSavedFormat), dialog.FileName);
            });
    }

    [RelayCommand(CanExecute = nameof(CanManageState))]
    private async Task LoadStateAsync()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = $"{UiText.ExportAuditState}|*.audit.json|{UiText.ExportAllJson}|*.json",
            DefaultExt = ".audit.json"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var state = await AuditState.LoadFromFileAsync(dialog.FileName);
                if (state is null)
                {
                    ScanStatus = UiText.StateLoadFailed;
                    return;
                }

                var restored = ApplyAuditState(state);
                ScanStatus = UiText.Format(
                    nameof(UiText.StateLoadedFormat), restored, Path.GetFileName(dialog.FileName));
            }
            catch (InvalidDataException ex)
            {
                AppendActivity(UiText.Format(nameof(UiText.StateLoadRejectedFormat), ex.Message));
                ScanStatus = UiText.Format(nameof(UiText.StateNotLoadedFormat), ex.Message);
            }
            catch (Exception ex)
            {
                var logPath = Services.CrashLogWriter.Write(ex, "LoadStateAsync");
                ScanStatus = UiText.Format(nameof(UiText.StateLoadFailedWithLogFormat), logPath);
            }
        }
    }

    internal int ApplyAuditState(AuditState state)
    {
        ValidateAuditState(state);

        if (Enum.TryParse<ScanProfileType>(state.ScanProfile, ignoreCase: true, out var profile))
            SelectedProfile = profile;

        if (AvailableThemes.Contains(state.Theme, StringComparer.OrdinalIgnoreCase))
            SelectedTheme = AvailableThemes.First(theme => theme.Equals(state.Theme, StringComparison.OrdinalIgnoreCase));

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
            vm.RemediationDueDate = ParseStateRemediationDueDate(cs.RemediationDueDate);
            restored++;
        }

        UpdateScoreCounts();
        HasUnsavedChanges = false;
        return restored;
    }

    private void ValidateAuditState(AuditState state)
    {
        if (state is null)
            throw new InvalidDataException(UiText.StatePayloadEmpty);

        if (!string.Equals(state.SchemaVersion, AuditState.CurrentSchemaVersion, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(UiText.Format(
                nameof(UiText.StateSchemaUnsupportedFormat), state.SchemaVersion, AuditState.CurrentSchemaVersion));

        if (string.IsNullOrWhiteSpace(state.Client))
            throw new InvalidDataException(UiText.StateIdentityMissing);

        if (!string.IsNullOrWhiteSpace(Environment.ComputerName) &&
            !state.Client.Equals(Environment.ComputerName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(UiText.Format(
                nameof(UiText.StateWrongMachineFormat), state.Client, Environment.ComputerName));

        if (string.IsNullOrWhiteSpace(state.ToolVersion))
            throw new InvalidDataException(UiText.StateToolVersionMissing);

        if (state.SavedAt == default)
            throw new InvalidDataException(UiText.StateTimestampMissing);

        if (!Enum.TryParse<ScanProfileType>(state.ScanProfile, ignoreCase: true, out var profile) ||
            !AvailableProfiles.Contains(profile))
            throw new InvalidDataException(UiText.Format(nameof(UiText.StateProfileUnsupportedFormat), state.ScanProfile));

        if (!AvailableThemes.Contains(state.Theme, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException(UiText.Format(nameof(UiText.StateThemeUnsupportedFormat), state.Theme));

        if (state.Checks is null)
            throw new InvalidDataException(UiText.StateChecksMissing);

        var currentChecks = Checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unknown = new List<string>();

        foreach (var checkState in state.Checks)
        {
            if (string.IsNullOrWhiteSpace(checkState.Id))
                throw new InvalidDataException(UiText.StateCheckIdMissing);

            if (!seen.Add(checkState.Id))
                throw new InvalidDataException(UiText.Format(nameof(UiText.StateDuplicateCheckFormat), checkState.Id));

            if (!currentChecks.ContainsKey(checkState.Id))
                unknown.Add(checkState.Id);

            if (!Enum.IsDefined(checkState.Status))
                throw new InvalidDataException(UiText.Format(nameof(UiText.StateInvalidStatusFormat), checkState.Id));
        }

        if (unknown.Count > 0)
            throw new InvalidDataException(UiText.Format(
                nameof(UiText.StateUnknownChecksFormat), string.Join(", ", unknown.Take(5))));

        var missing = currentChecks.Keys.Where(id => !seen.Contains(id)).Take(5).ToArray();
        if (seen.Count != currentChecks.Count)
            throw new InvalidDataException(UiText.Format(
                nameof(UiText.StateIncompleteFormat), string.Join(", ", missing)));
    }

    private bool CanManageState() => !IsScanning && !IsExporting;

    private static DateTime? ParseStateRemediationDueDate(string? value)
    {
        if (DateTime.TryParseExact(
            value,
            "yyyy-MM-dd",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out var due))
        {
            return due.Date;
        }

        return null;
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

        foreach (var summary in CategoryRailItems.Where(s => s.Name.Equals(UiText.FilterAll, StringComparison.OrdinalIgnoreCase)))
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
        OnPropertyChanged(nameof(RansomwareGradeDisplay));
        OnPropertyChanged(nameof(RansomwareScoreDisplay));
        OnPropertyChanged(nameof(RansomwareBrushKey));
        OnPropertyChanged(nameof(DomainMaturityGradeDisplay));
        OnPropertyChanged(nameof(DomainMaturityScoreDisplay));
        OnPropertyChanged(nameof(DomainMaturityBrushKey));
        NotifyExportCommandCanExecuteChanged();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SelectedCategory = UiText.FilterAll;
        SearchText = "";
        StatusFilter = UiText.FilterAll;
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

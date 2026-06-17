using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;

namespace NetworkSecurityAuditor.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private CancellationTokenSource? _scanCts;

    public ObservableCollection<CheckItemViewModel> Checks { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteredChecks))]
    private string _selectedCategory = "All";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteredChecks))]
    private bool _isScanning;

    [ObservableProperty]
    private string _scanStatus = "Ready";

    [ObservableProperty]
    private ScanProfileType _selectedProfile = ScanProfileType.Full;

    [ObservableProperty]
    private string _selectedTheme = "Catppuccin Mocha";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Grade), nameof(GradeColor))]
    private int _overallScore;

    [ObservableProperty]
    private int _passCount;

    [ObservableProperty]
    private int _failCount;

    [ObservableProperty]
    private int _partialCount;

    [ObservableProperty]
    private int _naCount;

    [ObservableProperty]
    private int _ransomwareScore;

    [ObservableProperty]
    private string _ransomwareGrade = "N/A";

    [ObservableProperty]
    private int _domainMaturityScore;

    [ObservableProperty]
    private string _domainMaturityGrade = "N/A";

    public string[] Categories { get; private set; } = ["All"];

    public string[] AvailableThemes { get; } = ["Catppuccin Mocha"];

    public ScanProfileType[] AvailableProfiles { get; } = Enum.GetValues<ScanProfileType>();

    public IEnumerable<CheckItemViewModel> FilteredChecks =>
        SelectedCategory == "All"
            ? Checks
            : Checks.Where(c => c.Category == SelectedCategory);

    public string Grade => RiskScoreEngine.GradeFromScore(OverallScore);

    public string GradeColor => Grade switch
    {
        "A" => "#a6e3a1",
        "B" => "#94e2d5",
        "C" => "#f9e2af",
        "D" => "#fab387",
        "F" => "#f38ba8",
        _ => "#9399b2"
    };

    public EnvironmentInfo Environment { get; set; } = new();

    public void LoadCheckCatalog()
    {
        Checks.Clear();
        foreach (var meta in CheckCatalog.All.Values.OrderBy(m => m.Id))
        {
            Checks.Add(CheckItemViewModel.FromMetadata(meta));
        }

        Categories = ["All", .. CheckCatalog.Categories];
        OnPropertyChanged(nameof(Categories));
        OnPropertyChanged(nameof(FilteredChecks));
        UpdateScoreCounts();
    }

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        if (IsScanning) return;

        _scanCts = new CancellationTokenSource();
        IsScanning = true;
        ScanStatus = "Scanning...";

        var options = new AuditOptions
        {
            ScanProfile = SelectedProfile
        };

        var allChecks = CheckRegistry.GetAllChecks();
        var runner = new CheckRunner(allChecks);
        var completed = 0;
        var checkLookup = Checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);

        var progress = new Progress<(string checkId, CheckResult result)>(update =>
        {
            if (checkLookup.TryGetValue(update.checkId, out var vm))
            {
                vm.Status = update.result.Status;
                vm.Findings = update.result.Findings;
                vm.Evidence = update.result.Evidence;
                vm.IsRunning = false;
            }

            completed++;
            UpdateScoreCounts();
        });

        foreach (var vm in Checks) vm.IsRunning = false;

        try
        {
            var profileIds = ScanProfiles.Resolve(options.ScanProfile);
            foreach (var id in profileIds)
            {
                if (checkLookup.TryGetValue(id, out var vm))
                {
                    vm.IsRunning = true;
                    ScanStatus = $"Running {id}: {vm.Label} ({completed + 1}/{profileIds.Length})";
                }
            }

            await runner.RunAsync(Environment, options, progress, _scanCts.Token);
        }
        catch (OperationCanceledException)
        {
            // User cancelled
        }
        finally
        {
            foreach (var vm in Checks) vm.IsRunning = false;
            IsScanning = false;
            var total = ScanProfiles.Resolve(options.ScanProfile).Length;
            ScanStatus = _scanCts.Token.IsCancellationRequested
                ? $"Scan cancelled ({completed}/{total} completed)"
                : $"Scan complete ({completed}/{total} checks)";
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
    }

    private bool CanStopScan() => IsScanning;

    [RelayCommand]
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
            var html = Export.HtmlReportGenerator.Generate(Checks, Environment, OverallScore, Grade, RansomwareScore, RansomwareGrade, DomainMaturityScore, DomainMaturityGrade);
            await File.WriteAllTextAsync(dialog.FileName, html);
            ScanStatus = $"HTML report exported: {dialog.FileName}";
        }
    }

    [RelayCommand]
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
            var json = Export.JsonExporter.Export(Checks, Environment, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile, DomainMaturityScore, DomainMaturityGrade);
            await File.WriteAllTextAsync(dialog.FileName, json);
            ScanStatus = $"JSON report exported: {dialog.FileName}";
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
                RansomwareGrade = RansomwareGrade
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
    }

    private void UpdateScoreCounts()
    {
        PassCount = Checks.Count(c => c.Status == CheckStatus.Pass);
        FailCount = Checks.Count(c => c.Status == CheckStatus.Fail);
        PartialCount = Checks.Count(c => c.Status == CheckStatus.Partial);
        NaCount = Checks.Count(c => c.Status is CheckStatus.NA or CheckStatus.NotAssessed);

        var (score, _) = RiskScoreEngine.Calculate(Checks);
        OverallScore = score;

        var (rwScore, rwGrade) = RansomwareReadinessEngine.Calculate(Checks);
        RansomwareScore = rwScore;
        RansomwareGrade = rwGrade;

        var (dmScore, dmGrade, _) = DomainMaturityEngine.Calculate(Checks);
        DomainMaturityScore = dmScore;
        DomainMaturityGrade = dmGrade;

        OnPropertyChanged(nameof(FilteredChecks));
    }
}

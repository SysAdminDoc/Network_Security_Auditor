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

        var totalChecks = Checks.Count;
        var completed = 0;

        try
        {
            foreach (var checkVm in Checks)
            {
                if (_scanCts.Token.IsCancellationRequested) break;

                checkVm.IsRunning = true;
                ScanStatus = $"Running {checkVm.Id}: {checkVm.Label} ({completed + 1}/{totalChecks})";

                ISecurityCheck check = new StubCheck(checkVm.Id);

                try
                {
                    var result = await check.ExecuteAsync(Environment, options, _scanCts.Token);
                    checkVm.Status = result.Status;
                    checkVm.Findings = result.Findings;
                    checkVm.Evidence = result.Evidence;
                }
                catch (OperationCanceledException)
                {
                    checkVm.Status = CheckStatus.NA;
                    checkVm.Findings = "Scan cancelled by user.";
                    break;
                }
                catch (Exception ex)
                {
                    checkVm.Status = CheckStatus.NA;
                    checkVm.Findings = $"Error: {ex.Message}";
                }
                finally
                {
                    checkVm.IsRunning = false;
                    completed++;
                }

                UpdateScoreCounts();
            }
        }
        finally
        {
            IsScanning = false;
            ScanStatus = _scanCts.Token.IsCancellationRequested
                ? $"Scan cancelled ({completed}/{totalChecks} completed)"
                : $"Scan complete ({completed}/{totalChecks} checks)";
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
            var html = Export.HtmlReportGenerator.Generate(Checks, Environment, OverallScore, Grade, RansomwareScore, RansomwareGrade);
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
            var json = Export.JsonExporter.Export(Checks, Environment, OverallScore, Grade, RansomwareScore, RansomwareGrade, SelectedProfile);
            await File.WriteAllTextAsync(dialog.FileName, json);
            ScanStatus = $"JSON report exported: {dialog.FileName}";
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

        OnPropertyChanged(nameof(FilteredChecks));
    }
}

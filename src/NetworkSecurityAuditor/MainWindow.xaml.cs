using System.Windows;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        Title = $"Network Security Auditor v{VersionInfo.Version}";
        DataContext = _viewModel;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        _viewModel.ScanStatus = "Detecting environment...";
        _viewModel.LoadCheckCatalog();
        _viewModel.Environment = await Task.Run(EnvironmentDetector.Detect);
        _viewModel.RunPreflight();
    }
}

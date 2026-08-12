using System.Collections.Specialized;
using System.Windows;
using System.Windows.Threading;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.Localization;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private readonly bool _activityAutoFollowEnabled;

    public MainWindow(bool enableActivityAutoFollow = true)
    {
        InitializeComponent();
        _activityAutoFollowEnabled = enableActivityAutoFollow;
        Title = UiText.Format(nameof(UiText.WindowTitleFormat), UiText.AppName, VersionInfo.Version);
        DataContext = _viewModel;
        ThemeManager.SystemContrastChanged += OnSystemContrastChanged;
        Loaded += OnLoaded;
        Closed += OnClosed;
        if (_activityAutoFollowEnabled)
            _viewModel.ActivityLog.CollectionChanged += OnActivityLogChanged;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        _viewModel.ScanStatus = "Detecting environment...";
        _viewModel.LoadCheckCatalog();
        _viewModel.Environment = await Task.Run(EnvironmentDetector.Detect);
        _viewModel.RunPreflight();
    }

    private void OnActivityLogChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(ActivityLogScrollViewer.ScrollToEnd, DispatcherPriority.Background);
    }

    private void OnSystemContrastChanged(object? sender, EventArgs e)
    {
        _viewModel.RefreshThemeResources();
    }

    private async void OnClosed(object? sender, EventArgs e)
    {
        if (_activityAutoFollowEnabled)
            _viewModel.ActivityLog.CollectionChanged -= OnActivityLogChanged;
        ThemeManager.SystemContrastChanged -= OnSystemContrastChanged;
        Closed -= OnClosed;
        await _viewModel.ShutdownAsync(TimeSpan.FromSeconds(5));
    }
}

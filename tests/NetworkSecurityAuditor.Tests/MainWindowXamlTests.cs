namespace NetworkSecurityAuditor.Tests;

public class MainWindowXamlTests
{
    [Fact]
    public void Main_Window_Binds_Security_Color_Surfaces()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("Foreground=\"{Binding GradeBrushKey, Converter={StaticResource ResourceBrush}}\"", xaml);
        Assert.Contains("Background=\"{Binding SeverityBrushKey, Converter={StaticResource ResourceBrush}}\"", xaml);
        Assert.Contains("Background=\"{Binding StatusBrushKey, Converter={StaticResource ResourceBrush}}\"", xaml);
    }

    [Fact]
    public void Main_Window_Surfaces_Manual_Assessment_Controls()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("Text=\"{Binding SearchText, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding StatusFilters}\"", xaml);
        Assert.Contains("IsChecked=\"{Binding PrivacyMode}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding AvailableThemes}\"", xaml);
        Assert.Contains("Text=\"{Binding DomainMaturityGrade}\"", xaml);
        Assert.Contains("Path=\"DomainMaturityScore\"", xaml);
        Assert.Contains("Command=\"{Binding SaveStateCommand}\"", xaml);
        Assert.Contains("Command=\"{Binding LoadStateCommand}\"", xaml);
        Assert.Contains("VerticalScrollBarVisibility=\"Auto\"", xaml);
    }

    [Fact]
    public void Main_Window_Uses_Not_Scanned_Overall_Score_Display()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("Text=\"{Binding OverallScoreDisplay}\"", xaml);
        Assert.DoesNotContain("Path=\"OverallScore\" StringFormat=\"{}{0}/100\"", xaml);
    }

    [Fact]
    public void Main_Window_Uses_Dark_Due_Date_Text_Field()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var theme = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");

        Assert.DoesNotContain("<DatePicker", xaml);
        Assert.Contains("Text=\"{Binding RemediationDueDate, StringFormat={}{0:yyyy-MM-dd}, TargetNullValue='', UpdateSourceTrigger=LostFocus, ValidatesOnExceptions=True, NotifyOnValidationError=True}\"", xaml);
        Assert.Contains("Style=\"{StaticResource DarkTextBox}\"", xaml);
        Assert.Contains("Property=\"Validation.ErrorTemplate\"", theme);
        Assert.Contains("Path=(Validation.Errors)[0].ErrorContent", theme);
    }

    [Fact]
    public void Main_Window_Uses_Accessible_Muted_Text_And_Square_Thin_Bar()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var theme = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");

        Assert.Contains("x:Key=\"TextMuted\" Color=\"#a6adc8\"", theme);
        Assert.DoesNotContain("Foreground=\"{StaticResource BorderDim}\"", xaml);
        Assert.Contains("Foreground=\"{StaticResource TextMuted}\"", xaml);
        Assert.Contains("Height=\"3\" CornerRadius=\"0\"", xaml);
        Assert.DoesNotContain("Height=\"3\" CornerRadius=\"2\"", xaml);
    }

    [Fact]
    public void Main_Window_Uses_Theme_Tokens_For_Dynamic_Color_Surfaces()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var app = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml");
        var theme = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");
        var checkVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "CheckItemViewModel.cs");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("ResourceBrushConverter x:Key=\"ResourceBrush\"", app);
        Assert.Contains("x:Key=\"OverlayScrim\" Color=\"#881e1e2e\"", theme);
        Assert.Contains("x:Key=\"BadgeBg\" Color=\"#585b70\"", theme);
        Assert.Contains("x:Key=\"OnAccent\" Color=\"#1e1e2e\"", theme);
        Assert.Contains("Background=\"{StaticResource OverlayScrim}\"", xaml);
        Assert.DoesNotContain("Background=\"#881e1e2e\"", xaml);
        Assert.DoesNotMatch("#[0-9a-fA-F]{6,8}", checkVm);
        Assert.DoesNotMatch("#[0-9a-fA-F]{6,8}", mainVm);
    }

    [Fact]
    public void Main_Window_Uses_Virtualized_Check_List()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("<ListBox Grid.Column=\"1\" Grid.Row=\"0\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding FilteredChecks}\"", xaml);
        Assert.Contains("VirtualizingPanel.IsVirtualizing=\"True\"", xaml);
        Assert.Contains("VirtualizingPanel.VirtualizationMode=\"Recycling\"", xaml);
        Assert.Contains("<VirtualizingStackPanel />", xaml);
        Assert.DoesNotContain("<ItemsControl ItemsSource=\"{Binding FilteredChecks}\">", xaml);
        Assert.Contains("public ICollectionView FilteredChecks { get; }", mainVm);
        Assert.Contains("CollectionViewSource.GetDefaultView(Checks)", mainVm);
        Assert.DoesNotContain("NotifyPropertyChangedFor(nameof(FilteredChecks))", mainVm);
        Assert.DoesNotContain("IEnumerable<CheckItemViewModel> FilteredChecks", mainVm);
    }

    [Fact]
    public void Main_Window_Detects_Environment_Off_Dispatcher()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml.cs");

        Assert.Contains("private async void OnLoaded", source);
        Assert.Contains("await Task.Run(EnvironmentDetector.Detect)", source);
        Assert.DoesNotContain("_viewModel.Environment = EnvironmentDetector.Detect();", source);
    }

    [Fact]
    public void Theme_Provides_Dark_Popup_Control_Templates()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");

        Assert.Contains("x:Key=\"DarkCheckBox\"", xaml);
        Assert.Contains("x:Key=\"DarkComboBoxItem\"", xaml);
        Assert.Contains("ControlTemplate TargetType=\"ComboBox\"", xaml);
        Assert.Contains("x:Name=\"PART_Popup\"", xaml);
        Assert.Contains("TargetType=\"ScrollBar\"", xaml);
        Assert.Contains("ControlTemplate TargetType=\"ToolTip\"", xaml);
        Assert.Contains("ControlTemplate TargetType=\"ContextMenu\"", xaml);
    }

    private static string ReadSourceFile(params string[] segments)
    {
        var pathSegments = new string[segments.Length + 1];
        pathSegments[0] = FindRepoRoot();
        Array.Copy(segments, 0, pathSegments, 1, segments.Length);
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

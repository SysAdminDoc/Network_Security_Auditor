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
        Assert.Contains("Foreground=\"{Binding StatusForegroundBrushKey, Converter={StaticResource ResourceBrush}}\"", xaml);
    }

    [Fact]
    public void Main_Window_Surfaces_Manual_Assessment_Controls()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("Text=\"{Binding SearchText, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("Search ID, check, or category", xaml);
        Assert.Contains("Text=\"{Binding VisibleChecksDisplay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding StatusFilters}\"", xaml);
        Assert.Contains("IsChecked=\"{Binding PrivacyMode}\"", xaml);
        Assert.Contains("Text=\"{Binding DomainMaturityGrade}\"", xaml);
        Assert.Contains("Text=\"{Binding DomainMaturityScore, StringFormat={}{0}/100}\"", xaml);
        Assert.Contains("Command=\"{Binding SaveStateCommand}\"", xaml);
        Assert.Contains("Command=\"{Binding LoadStateCommand}\"", xaml);
        Assert.Contains("VerticalScrollBarVisibility=\"Auto\"", xaml);
        Assert.Contains("Content=\"{Binding SelectedCheck}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding CategoryRailItems}\"", xaml);
        Assert.Contains("Text=\"{Binding NotApplicableCount, StringFormat=N/A: {0}}\"", xaml);
        Assert.Contains("Text=\"{Binding NotAssessedCount, StringFormat=Not assessed: {0}}\"", xaml);
    }

    [Fact]
    public void Main_Window_Uses_Not_Scanned_Overall_Score_Display()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("Text=\"{Binding OverallScoreDisplay}\"", xaml);
        Assert.Contains("Text=\"{Binding ScoreSubtitle}\"", xaml);
        Assert.DoesNotContain("Path=\"OverallScore\" StringFormat=\"{}{0}/100\"", xaml);
        Assert.Contains("Text=\"{Binding ScanProgressDisplay}\"", xaml);
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

        Assert.Contains("x:Key=\"TextMuted\" Color=\"#9aa7bd\"", theme);
        Assert.DoesNotContain("Foreground=\"{StaticResource BorderDim}\"", xaml);
        Assert.Contains("Foreground=\"{StaticResource TextMuted}\"", xaml);
        Assert.Contains("Height=\"5\"", xaml);
        Assert.Contains("Style x:Key=\"PremiumCard\"", theme);
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
        Assert.Contains("x:Key=\"OverlayScrim\" Color=\"#aa0f141d\"", theme);
        Assert.Contains("x:Key=\"BadgeBg\" Color=\"#273244\"", theme);
        Assert.Contains("x:Key=\"OnAccent\" Color=\"#f8fafc\"", theme);
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

        Assert.Contains("SelectedItem=\"{Binding SelectedCheck, Mode=TwoWay}\"", xaml);
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
    public void Main_Window_Export_Commands_Use_CanExport_Gate()
    {
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("private bool CanExport() => !IsScanning && !IsExporting && HasAssessedChecks && !string.IsNullOrWhiteSpace(ExportOutputFolder);", mainVm);
        Assert.Equal(13, mainVm.Split("[RelayCommand(CanExecute = nameof(CanExport))]").Length - 1);
        Assert.Contains("ExportSelectedCommand.NotifyCanExecuteChanged();", mainVm);
        Assert.Contains("NotifyExportCommandCanExecuteChanged();", mainVm);
        Assert.Contains("ExportAvailabilityText", mainVm);
    }

    [Fact]
    public void Main_Window_Uses_Compact_Export_Settings_Flow()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");
        var exportOption = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "ExportFormatOption.cs");

        Assert.Contains("Content=\"Export\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding ExportFormats}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedExportFormat}\"", xaml);
        Assert.Contains("Text=\"{Binding ExportOutputFolder, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("ToolTip=\"{Binding ExportAvailabilityText}\"", xaml);
        Assert.Contains("ToolTipService.ShowOnDisabled=\"True\"", xaml);
        Assert.Contains("Command=\"{Binding BrowseExportFolderCommand}\"", xaml);
        Assert.Contains("Command=\"{Binding ExportSelectedCommand}\"", xaml);
        Assert.DoesNotContain("Command=\"{Binding ExportHtmlCommand}\"", xaml);
        Assert.Contains("ExportFormatKind.SiemContentPack", mainVm);
        Assert.Contains("ExportFormatKind.CmmcHtml", mainVm);
        Assert.Contains("ExportFormatKind.CmmcJson", mainVm);
        Assert.Contains("public enum ExportFormatKind", exportOption);
    }

    [Fact]
    public void Main_Window_Uses_Premium_Workstation_Layout()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var theme = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("Category progress navigation", xaml);
        Assert.Contains("Selected check evidence and remediation inspector", xaml);
        Assert.Contains("Activity Console", xaml);
        Assert.Contains("ActivityLog", xaml);
        Assert.Contains("CategoryRailItems", xaml);
        Assert.Contains("TargetDisplay", xaml);
        Assert.Contains("FilterEmptyStateTitle", xaml);
        Assert.Contains("ClearFiltersCommand", xaml);
        Assert.Contains("ScanReadinessText", xaml);
        Assert.Contains("x:Key=\"InspectorCard\"", theme);
        Assert.Contains("public ObservableCollection<CategorySummaryViewModel> CategorySummaries { get; }", mainVm);
        Assert.Contains("public ObservableCollection<string> ActivityLog { get; }", mainVm);
    }

    [Fact]
    public void Main_Window_Uses_Friendly_Status_Labels()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");
        var app = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml");
        var converter = ReadSourceFile("src", "NetworkSecurityAuditor", "Converters", "CheckStatusLabelConverter.cs");

        Assert.Contains("CheckStatusLabelConverter x:Key=\"CheckStatusLabel\"", app);
        Assert.Contains("Converter={StaticResource CheckStatusLabel}", xaml);
        Assert.Contains("CheckStatus.NotAssessed => \"Not assessed\"", converter);
        Assert.Contains("CheckStatus.NA => \"N/A\"", converter);
    }

    [Fact]
    public void Theme_Provides_Keyboard_Focus_States()
    {
        var theme = ReadSourceFile("src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");

        Assert.Contains("Property=\"IsKeyboardFocused\" Value=\"True\"", theme);
        Assert.Contains("Property=\"IsKeyboardFocusWithin\" Value=\"True\"", theme);
        Assert.Contains("x:Key=\"AccentSoft\"", theme);
        Assert.Contains("x:Key=\"RailBg\"", theme);
        Assert.Contains("Property=\"ToolTipService.ShowOnDisabled\" Value=\"True\"", theme);
        Assert.DoesNotContain("TargetName=\"ButtonBorder\" Property=\"BorderThickness\" Value=\"1\"", theme);
    }

    [Fact]
    public void Main_Window_Announces_Dynamic_Scan_And_Filter_States()
    {
        var xaml = ReadSourceFile("src", "NetworkSecurityAuditor", "MainWindow.xaml");

        Assert.Contains("AutomationProperties.LiveSetting=\"Polite\"", xaml);
        Assert.Contains("AutomationProperties.Name=\"Scan progress\"", xaml);
        Assert.Contains("AutomationProperties.Name=\"No matching checks\"", xaml);
        Assert.Contains("AutomationProperties.Name=\"Filtered check count\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"CategoryRail\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"ScanProfileSelector\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"StartScanButton\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"StopScanButton\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"ExportFormatSelector\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"ExportSelectedFormatButton\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"StatusFilter\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"CheckSearchBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"FilteredChecksList\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"SelectedCheckInspector\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorStatusSelector\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorFindingsTextBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorEvidenceTextBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorNotesTextBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorAssigneeTextBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"InspectorDueDateTextBox\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"ActivityLogList\"", xaml);
        Assert.Contains("Fail: {0}", xaml);
        Assert.Contains("Partial: {0}", xaml);
        Assert.Contains("Pass: {0}", xaml);
    }

    [Fact]
    public void Main_Window_Documents_Csharp_Theme_Surface_As_Catppuccin_Only()
    {
        var readme = ReadSourceFile("README.md");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("public string[] AvailableThemes { get; } = [\"Catppuccin Mocha\"];", mainVm);
        Assert.Contains("Catppuccin Mocha dark theme", readme);
        Assert.Contains("legacy PowerShell WPF artifact retains the seven-theme selector", readme);
        Assert.DoesNotContain("**7 dark themes**", readme);
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
    public void App_Provides_Background_Uia_Launch_Flag()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml.cs");

        Assert.Contains("--uia-background", source);
        Assert.Contains("--render-screenshot", source);
        Assert.Contains("RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;", source);
        Assert.Contains("window.Left = -32000;", source);
        Assert.Contains("window.ShowActivated = false;", source);
        Assert.Contains("window.ShowInTaskbar = false;", source);
        Assert.Contains("RenderTargetBitmap", source);
    }

    [Fact]
    public void Unavailable_Profile_Copy_Does_Not_Leak_Rewrite_History()
    {
        var app = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml.cs");
        var mainVm = ReadSourceFile("src", "NetworkSecurityAuditor", "ViewModels", "MainViewModel.cs");

        Assert.Contains("is not available in this preview", app);
        Assert.Contains("is not available in this preview", mainVm);
        Assert.DoesNotContain("not implemented in the C# rewrite yet", app);
        Assert.DoesNotContain("not implemented in the C# rewrite yet", mainVm);
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

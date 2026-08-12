namespace NetworkSecurityAuditor.Tests;

using System.Runtime.ExceptionServices;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Xml.Linq;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.ViewModels;

[Collection(NonParallelTestCollection.Name)]
public sealed class HighContrastThemeTests
{
    [Fact]
    public void High_Contrast_Overrides_Every_Semantic_Brush_With_Dynamic_System_Colors()
    {
        var defaultThemePath = SourcePath("Theme", "Themes.xaml");
        var highContrastPath = SourcePath("Theme", "HighContrast.xaml");
        var defaultTheme = XDocument.Load(defaultThemePath);
        var highContrast = XDocument.Load(highContrastPath);
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

        var defaultKeys = defaultTheme
            .Descendants(presentation + "SolidColorBrush")
            .Select(element => element.Attribute(xaml + "Key")?.Value)
            .Where(key => key is not null)
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();
        var highContrastBrushes = highContrast
            .Descendants(presentation + "SolidColorBrush")
            .ToArray();
        var highContrastKeys = highContrastBrushes
            .Select(element => element.Attribute(xaml + "Key")?.Value)
            .Where(key => key is not null)
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(defaultKeys, highContrastKeys);
        Assert.All(
            highContrastBrushes,
            brush =>
            {
                var color = brush.Attribute("Color")?.Value ?? "";
                Assert.Contains("DynamicResource", color);
                Assert.Contains("SystemColors.", color);
                Assert.EndsWith("ColorKey}}", color, StringComparison.Ordinal);
            });
        Assert.DoesNotMatch("#[0-9a-fA-F]{6,8}", File.ReadAllText(highContrastPath));
    }

    [Fact]
    public void High_Contrast_Dictionary_Loads_And_All_Custom_Control_Templates_Parse()
    {
        if (!OperatingSystem.IsWindows())
            return;

        RunSta(() =>
        {
            var resources = new ResourceDictionary();
            var defaultTheme = LoadDictionary(SourcePath("Theme", "Themes.xaml"));
            resources.MergedDictionaries.Add(defaultTheme);

            var highContrast = LoadDictionary(SourcePath("Theme", "HighContrast.xaml"));
            resources.MergedDictionaries.Add(highContrast);

            Assert.Equal(2, resources.MergedDictionaries.Count);
            Assert.True((bool)highContrast["SystemContrastOverrideActive"]);
            Assert.IsType<System.Windows.Media.SolidColorBrush>(highContrast["WindowBg"]);
            Assert.IsType<System.Windows.Media.SolidColorBrush>(highContrast["SelectionBg"]);

            object[] templateStyleKeys =
            [
                "DarkScrollBarThumb",
                "DarkScrollBarPageButton",
                typeof(ScrollBar),
                "DarkCheckBox",
                "DarkComboBoxItem",
                "DarkComboBox",
                typeof(ToolTip),
                typeof(MenuItem),
                typeof(ContextMenu),
                "AccentButton",
                "SecondaryButton",
                "DarkListBoxItem",
            ];
            foreach (var key in templateStyleKeys)
            {
                var style = Assert.IsType<Style>(defaultTheme[key]);
                Assert.Contains(
                    style.Setters.OfType<Setter>(),
                    setter => setter.Property == Control.TemplateProperty && setter.Value is ControlTemplate);
            }

            Assert.False((bool)defaultTheme["SystemContrastOverrideActive"]);
        });
    }

    [Fact]
    public void Theme_Manager_Adds_One_Override_And_Restores_Default_Resources()
    {
        RunSta(() =>
        {
            var application = new App();
            application.InitializeComponent();
            var defaultTheme = application.Resources.MergedDictionaries.Single();

            ThemeManager.Apply(application.Resources, highContrast: true);
            ThemeManager.Apply(application.Resources, highContrast: true);

            Assert.Equal(2, application.Resources.MergedDictionaries.Count);
            Assert.Equal(ThemeManager.HighContrastResourceUri, application.Resources.MergedDictionaries[^1].Source);

            ThemeManager.Apply(application.Resources, highContrast: false);
            Assert.Single(application.Resources.MergedDictionaries);
            Assert.Same(defaultTheme, application.Resources.MergedDictionaries[0]);
            application.Shutdown();
        });
    }

    [Fact]
    public void Theme_Manager_Uses_Windows_High_Contrast_At_Startup_And_Tracks_Runtime_Changes()
    {
        var source = File.ReadAllText(SourcePath("Services", "ThemeManager.cs"));

        Assert.Contains("Apply(application.Resources, SystemParameters.HighContrast);", source);
        Assert.Contains("SystemParameters.StaticPropertyChanged += OnSystemParameterChanged;", source);
        Assert.Contains("SystemParameters.StaticPropertyChanged -= OnSystemParameterChanged;", source);
        Assert.Contains("nameof(SystemParameters.HighContrast)", source);
        Assert.Contains("SystemContrastChanged?.Invoke", source);
    }

    [Fact]
    public void Theme_Change_Refreshes_All_Converter_Backed_Brush_Properties()
    {
        var check = CheckItemViewModel.FromMetadata(Data.CheckCatalog.All.Values.First());
        var category = new CategorySummaryViewModel { Name = "All" };
        var checkChanges = new List<string>();
        var categoryChanges = new List<string>();
        check.PropertyChanged += (_, e) => checkChanges.Add(e.PropertyName ?? "");
        category.PropertyChanged += (_, e) => categoryChanges.Add(e.PropertyName ?? "");

        check.RefreshThemeResources();
        category.RefreshThemeResources();

        Assert.Contains(nameof(CheckItemViewModel.StatusBrushKey), checkChanges);
        Assert.Contains(nameof(CheckItemViewModel.StatusForegroundBrushKey), checkChanges);
        Assert.Contains(nameof(CheckItemViewModel.SeverityBrushKey), checkChanges);
        Assert.Contains(nameof(CategorySummaryViewModel.HealthBrushKey), categoryChanges);
    }

    [Fact]
    public void Main_Window_Uses_Dynamic_Semantic_Brushes_And_Textual_Status_Cues()
    {
        var xaml = File.ReadAllText(SourcePath("MainWindow.xaml"));

        Assert.DoesNotMatch("\\{StaticResource (?:WindowBg|PanelBg|CardBg|Accent|TextPrimary|ProgressBad)\\}", xaml);
        Assert.Contains("{DynamicResource StatusOnColor}", xaml);
        Assert.Contains("Text=\"{Binding SeverityLabel}\"", xaml);
        Assert.Contains("Text=\"{Binding StatusLabel}\"", xaml);
        Assert.Contains("StringFormat=Pass: {0}", xaml);
        Assert.Contains("StringFormat=Partial: {0}", xaml);
        Assert.Contains("StringFormat=Fail: {0}", xaml);
        Assert.Contains("TargetName=\"FocusBorder\" Property=\"BorderThickness\" Value=\"2\"", xaml);
    }

    [Fact]
    public void Custom_Templates_Declare_Focus_Disabled_Selected_And_Error_Cues()
    {
        var theme = File.ReadAllText(SourcePath("Theme", "Themes.xaml"));
        var mainWindow = File.ReadAllText(SourcePath("MainWindow.xaml"));

        foreach (var state in new[]
                 {
                     "IsKeyboardFocused",
                     "IsKeyboardFocusWithin",
                     "IsEnabled",
                     "IsSelected",
                     "IsChecked",
                     "IsPressed",
                     "IsHighlighted",
                     "IsDragging",
                     "Validation.HasError",
                 })
        {
            Assert.Contains($"Property=\"{state}\"", theme + mainWindow);
        }

        Assert.Contains("{DynamicResource FocusRing}", theme);
        Assert.Contains("{DynamicResource CheckedFocusRing}", theme);
        Assert.Contains("{DynamicResource DisabledText}", theme);
        Assert.Contains("{DynamicResource SelectionBg}", theme);
        Assert.Contains("{DynamicResource SelectionText}", theme);
        Assert.Contains("{DynamicResource ErrorBorder}", theme);
        Assert.Contains("BorderThickness=\"2\"", theme);
        Assert.Contains("BorderThickness\" Value=\"3\"", theme);
    }

    private static string SourcePath(params string[] segments)
    {
        var allSegments = new string[segments.Length + 3];
        allSegments[0] = FindRepoRoot();
        allSegments[1] = "src";
        allSegments[2] = "NetworkSecurityAuditor";
        Array.Copy(segments, 0, allSegments, 3, segments.Length);
        return Path.Combine(allSegments);
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    private static void RunSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "STA resource-loading test timed out.");
        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static ResourceDictionary LoadDictionary(string path)
    {
        using var stream = File.OpenRead(path);
        return Assert.IsType<ResourceDictionary>(XamlReader.Load(stream));
    }
}

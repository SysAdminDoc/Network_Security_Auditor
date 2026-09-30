using System.Collections.ObjectModel;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Theme;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

[Collection(NonParallelTestCollection.Name)]
public class DesignTokenTests
{
    [Fact]
    public void Wpf_Theme_Brushes_Match_The_Shared_Design_Tokens()
    {
        RunSta(() =>
        {
            var dictionary = LoadDictionary(SourcePath("Theme", "Themes.xaml"));

            AssertBrushColor(dictionary, "GradeA", DesignTokens.GradeAColor);
            AssertBrushColor(dictionary, "GradeB", DesignTokens.GradeBColor);
            AssertBrushColor(dictionary, "GradeC", DesignTokens.GradeCColor);
            AssertBrushColor(dictionary, "GradeD", DesignTokens.GradeDColor);
            AssertBrushColor(dictionary, "GradeF", DesignTokens.GradeFColor);
            AssertBrushColor(dictionary, "SeverityCritical", DesignTokens.SeverityCriticalColor);
            AssertBrushColor(dictionary, "SeverityHigh", DesignTokens.SeverityHighColor);
            AssertBrushColor(dictionary, "SeverityMedium", DesignTokens.SeverityMediumColor);
            AssertBrushColor(dictionary, "SeverityLow", DesignTokens.SeverityLowColor);
            AssertBrushColor(dictionary, "StatusPass", DesignTokens.StatusPassColor);
            AssertBrushColor(dictionary, "StatusPartial", DesignTokens.StatusPartialColor);
            AssertBrushColor(dictionary, "StatusFail", DesignTokens.StatusFailColor);
            AssertBrushColor(dictionary, "StatusNa", DesignTokens.StatusNaColor);
            AssertBrushColor(dictionary, "StatusNotAssessed", DesignTokens.StatusNotAssessedColor);
            AssertBrushColor(dictionary, "StatusError", DesignTokens.StatusErrorColor);

            // Existing progress-bar brushes reuse the same pass/partial/fail identity colors.
            AssertBrushColor(dictionary, "ProgressGood", DesignTokens.StatusPassColor);
            AssertBrushColor(dictionary, "ProgressMid", DesignTokens.StatusPartialColor);
            AssertBrushColor(dictionary, "ProgressBad", DesignTokens.StatusFailColor);
        });
    }

    [Fact]
    public void Html_Report_Css_Uses_The_Shared_Design_Tokens_For_Severity_Status_And_Grade_Colors()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C", 60, "D");

        Assert.Contains($".dot.pass {{ background: {DesignTokens.StatusPassHex}; }}", html);
        Assert.Contains($".dot.partial {{ background: {DesignTokens.StatusPartialHex}; }}", html);
        Assert.Contains($".dot.fail {{ background: {DesignTokens.StatusFailHex}; }}", html);
        Assert.Contains($".severity-critical {{ background: rgba(243,139,168,0.2); color: {DesignTokens.SeverityCriticalHex}; }}", html);
        Assert.Contains($".status-pass {{ background: rgba(166,227,161,0.2); color: {DesignTokens.StatusPassHex}; }}", html);
        Assert.Contains($"color:{DesignTokens.GradeBHex}", html);
    }

    [Fact]
    public void Cmmc_Report_Status_Colors_Match_The_Shared_Design_Tokens()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(3))
            checks.Add(CheckItemViewModel.FromMetadata(meta));
        var env = new EnvironmentInfo { ComputerName = "TEST", IsDomainJoined = true, DomainName = "TEST.LOCAL" };

        var html = CmmcReportGenerator.ExportHtml(checks, env, 85, "B");

        Assert.Contains(DesignTokens.StatusPassHex, html);
        Assert.Contains(DesignTokens.StatusPartialHex, html);
        Assert.Contains(DesignTokens.StatusFailHex, html);
    }

    [Fact]
    public async Task Dashboard_Grade_Classes_Use_The_Shared_Design_Tokens()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nsa-design-token-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var html = await DashboardGenerator.GenerateAsync(dir);

            Assert.Contains($".grade-a {{ color: {DesignTokens.GradeAHex}; }}", html);
            Assert.Contains($".grade-b {{ color: {DesignTokens.GradeBHex}; }}", html);
            Assert.Contains($".grade-c {{ color: {DesignTokens.GradeCHex}; }}", html);
            Assert.Contains($".grade-d {{ color: {DesignTokens.GradeDHex}; }}", html);
            Assert.Contains($".grade-f {{ color: {DesignTokens.GradeFHex}; }}", html);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData(nameof(DesignTokens.StatusPassHex))]
    [InlineData(nameof(DesignTokens.StatusPartialHex))]
    [InlineData(nameof(DesignTokens.StatusFailHex))]
    [InlineData(nameof(DesignTokens.StatusErrorHex))]
    [InlineData(nameof(DesignTokens.SeverityCriticalHex))]
    [InlineData(nameof(DesignTokens.SeverityHighHex))]
    [InlineData(nameof(DesignTokens.GradeBHex))]
    public void Design_Tokens_Meet_Wcag_Contrast_Against_The_Report_Card_Background(string tokenFieldName)
    {
        var field = typeof(DesignTokens).GetField(tokenFieldName) ?? throw new MissingFieldException(tokenFieldName);
        var hex = (string)field.GetValue(null)!;

        // Every token is used as text/badge color on the report's #313244 card background.
        var ratio = Contrast(Parse(hex), Parse("#313244"));
        Assert.True(ratio >= 3.0, $"{tokenFieldName} ({hex}) on #313244 is {ratio:0.00}:1; expected at least 3.0:1.");
    }

    private static (ObservableCollection<CheckItemViewModel> checks, EnvironmentInfo env) CreateTestData()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(5))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Pass;
            checks.Add(vm);
        }

        var env = new EnvironmentInfo { ComputerName = "TESTPC", OSCaption = "Windows 11" };
        return (checks, env);
    }

    private static void AssertBrushColor(ResourceDictionary dictionary, string key, Color expected)
    {
        var brush = Assert.IsType<SolidColorBrush>(dictionary[key]);
        Assert.Equal(expected, brush.Color);
    }

    private static ResourceDictionary LoadDictionary(string path)
    {
        var xaml = File.ReadAllText(path)
            .Replace("clr-namespace:NetworkSecurityAuditor.Theme\"", "clr-namespace:NetworkSecurityAuditor.Theme;assembly=NetworkSecurityAuditor\"");
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(xaml));
        return Assert.IsType<ResourceDictionary>(XamlReader.Load(stream));
    }

    private static double Contrast(Rgb first, Rgb second)
    {
        var lighter = Math.Max(Luminance(first), Luminance(second));
        var darker = Math.Min(Luminance(first), Luminance(second));
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double Luminance(Rgb color) =>
        (0.2126 * Linear(color.Red)) + (0.7152 * Linear(color.Green)) + (0.0722 * Linear(color.Blue));

    private static double Linear(byte channel)
    {
        var value = channel / 255.0;
        return value <= 0.04045 ? value / 12.92 : Math.Pow((value + 0.055) / 1.055, 2.4);
    }

    private static Rgb Parse(string hex) => new(
        byte.Parse(hex.AsSpan(1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
        byte.Parse(hex.AsSpan(3, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
        byte.Parse(hex.AsSpan(5, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));

    private readonly record struct Rgb(byte Red, byte Green, byte Blue);

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
}

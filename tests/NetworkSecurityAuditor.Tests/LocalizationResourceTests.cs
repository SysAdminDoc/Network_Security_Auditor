using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Localization;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

[Collection(NonParallelTestCollection.Name)]
public sealed class LocalizationResourceTests
{
    [Fact]
    public void English_Catalog_Covers_Every_Named_UiText_Resource()
    {
        var properties = typeof(UiText)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(property => property.PropertyType == typeof(string))
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            properties,
            EnglishTextResourceProvider.Catalog.Keys.OrderBy(name => name, StringComparer.Ordinal));
        Assert.All(properties, key => Assert.False(string.IsNullOrWhiteSpace(UiText.Get(key))));
    }

    [Fact]
    public void MainWindow_User_Facing_Literals_Resolve_Through_UiText()
    {
        var xaml = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "NetworkSecurityAuditor", "MainWindow.xaml"));
        var literalAttribute = new Regex(
            "(?:Text|Content|Header|Title|ToolTip|AutomationProperties\\.(?:Name|HelpText))=\\\"(?!\\{|\\s*$)([^\\\"]+)\\\"",
            RegexOptions.CultureInvariant);

        var violations = literalAttribute.Matches(xaml)
            .Select(match => match.Value)
            .ToArray();

        Assert.Empty(violations);
        Assert.Contains("xmlns:loc=", xaml, StringComparison.Ordinal);
        Assert.Contains("x:Static loc:UiText.", xaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Provider_Switch_Changes_Display_Text_But_Preserves_Machine_Contracts()
    {
        var meta = CheckCatalog.All.Values.First();
        var check = CheckItemViewModel.FromMetadata(meta);
        check.Status = CheckStatus.Fail;
        check.Findings = "A finding";
        check.Evidence = "Evidence";
        var checks = new[] { check };
        var environment = new EnvironmentInfo
        {
            ComputerName = "HOST-01",
            OSCaption = "Windows 11",
            OSVersion = "24H2"
        };

        var baselineJson = JsonExporter.Export(checks, environment, 20, "F", 20, "F", ScanProfileType.Full);
        var baselineCsv = CsvExporter.Export(checks, environment, 20, "F");
        var baselineCmmcJson = CmmcReportGenerator.ExportJson(checks, environment);

        using (UiText.PushProvider(new DecoratingProvider()))
        {
            Assert.StartsWith("[StatusFail]", check.StatusLabel, StringComparison.Ordinal);

            var html = HtmlReportGenerator.Generate(checks, environment, 20, "F", 20, "F");
            Assert.Contains("[ReportDocumentTitle]", html, StringComparison.Ordinal);
            Assert.Contains("[StatusFail]", html, StringComparison.Ordinal);

            var switchedJson = JsonExporter.Export(checks, environment, 20, "F", 20, "F", ScanProfileType.Full);
            var switchedCsv = CsvExporter.Export(checks, environment, 20, "F");
            var switchedCmmcJson = CmmcReportGenerator.ExportJson(checks, environment);

            AssertMachineJsonFieldsEqual(baselineJson, switchedJson);
            Assert.Equal(CsvHeader(baselineCsv), CsvHeader(switchedCsv));
            Assert.Equal(CsvDataStatus(baselineCsv), CsvDataStatus(switchedCsv));
            AssertMachineCmmcFieldsEqual(baselineCmmcJson, switchedCmmcJson);
        }

        Assert.Equal("Fail", check.StatusLabel);
    }

    private static void AssertMachineJsonFieldsEqual(string baseline, string switched)
    {
        using var before = JsonDocument.Parse(baseline);
        using var after = JsonDocument.Parse(switched);
        var beforeRoot = before.RootElement;
        var afterRoot = after.RootElement;

        Assert.Equal(
            beforeRoot.EnumerateObject().Select(property => property.Name).OrderBy(name => name),
            afterRoot.EnumerateObject().Select(property => property.Name).OrderBy(name => name));
        Assert.Equal(
            beforeRoot.GetProperty("findings")[0].GetProperty("id").GetString(),
            afterRoot.GetProperty("findings")[0].GetProperty("id").GetString());
        Assert.Equal("Fail", afterRoot.GetProperty("findings")[0].GetProperty("status").GetString());
        Assert.Matches(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$",
            afterRoot.GetProperty("timestamp").GetString()!);
    }

    private static void AssertMachineCmmcFieldsEqual(string baseline, string switched)
    {
        using var before = JsonDocument.Parse(baseline);
        using var after = JsonDocument.Parse(switched);
        Assert.Equal(
            before.RootElement.GetProperty("controls").EnumerateArray().Select(control => control.GetProperty("status").GetString()),
            after.RootElement.GetProperty("controls").EnumerateArray().Select(control => control.GetProperty("status").GetString()));
        Assert.Equal("cmmc_self_assessment", after.RootElement.GetProperty("report_type").GetString());
    }

    private static string CsvHeader(string csv) =>
        csv.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)[1];

    private static string CsvDataStatus(string csv) =>
        csv.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)[2].Split(',')[4];

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    private sealed class DecoratingProvider : ITextResourceProvider
    {
        private readonly EnglishTextResourceProvider _english = new();

        public string Get(string key) => $"[{key}]{_english.Get(key)}";
    }
}

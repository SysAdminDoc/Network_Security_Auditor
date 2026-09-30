using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public sealed partial class HtmlReportAccessibilityTests
{
    private static (ObservableCollection<CheckItemViewModel> checks, EnvironmentInfo env) CreateTestData()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(5))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Pass;
            vm.Findings = "Test finding";
            vm.Evidence = "Test evidence";
            checks.Add(vm);
        }

        var env = new EnvironmentInfo
        {
            ComputerName = "TESTPC",
            OSCaption = "Windows 11 Enterprise",
            OSVersion = "24H2",
            IsDomainJoined = true,
            DomainName = "TEST.LOCAL"
        };

        return (checks, env);
    }

    [Fact]
    public void Html_Report_Has_Skip_Link_And_Landmarks()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C", 60, "D");

        Assert.Contains("<a href=\"#main-content\" class=\"skip-link\">Skip to main content</a>", html);
        Assert.Contains("<header class=\"header\">", html);
        Assert.Contains("<main id=\"main-content\">", html);
        Assert.Contains("</main>", html);
        Assert.Contains("<footer class=\"footer\">", html);
        // Skip link must be the very first element rendered in the body so it is the first stop for Tab.
        var bodyIndex = html.IndexOf("<body>", StringComparison.Ordinal);
        var skipIndex = html.IndexOf("<a href=\"#main-content\"", bodyIndex, StringComparison.Ordinal);
        var headerIndex = html.IndexOf("<header", StringComparison.Ordinal);
        Assert.True(bodyIndex < skipIndex && skipIndex < headerIndex);
    }

    [Fact]
    public void Html_Report_Has_Table_Of_Contents_Linking_To_Rendered_Sections()
    {
        var (checks, env) = CreateTestData();
        checks[0].Status = CheckStatus.Fail;
        var html = HtmlReportGenerator.Generate(checks, env, 50, "F", 30, "F", 20, "F");

        Assert.Contains("<nav class=\"toc\" aria-label=\"Table of contents\">", html);
        Assert.Contains("<a href=\"#executive-summary\">Executive Summary</a>", html);
        Assert.Contains("<a href=\"#top-findings\">Top Findings</a>", html);
        Assert.Contains("<a href=\"#score-by-category\">Score by Category</a>", html);
        Assert.Contains("<a href=\"#compliance-readiness\">Compliance Framework Readiness</a>", html);
        Assert.Contains("<a href=\"#remediation-roadmap\">Remediation Roadmap</a>", html);
        Assert.Contains("<a href=\"#detailed-findings\">Detailed Findings</a>", html);
        Assert.Contains("<a href=\"#d3fend-coverage\">MITRE D3FEND Defensive Coverage</a>", html);

        // Every href target in the TOC must resolve to an id that actually exists in the document.
        foreach (Match match in TocHrefRegex().Matches(html))
        {
            var id = match.Groups["id"].Value;
            Assert.Contains($"id=\"{id}\"", html);
        }
    }

    [Fact]
    public void Html_Report_Table_Of_Contents_Omits_Sections_Not_Rendered_For_Tier()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 50, "F", 30, "F", 20, "F", tier: ReportTier.Executive);

        Assert.Contains("<a href=\"#executive-summary\">Executive Summary</a>", html);
        Assert.DoesNotContain("href=\"#detailed-findings\"", html);
        Assert.DoesNotContain("href=\"#score-by-category\"", html);
        // No failures were injected, so Top Findings should not appear in the TOC either.
        Assert.DoesNotContain("href=\"#top-findings\"", html);
    }

    [Fact]
    public void Html_Report_Detailed_Findings_Have_Per_Check_Anchors()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C");

        foreach (var check in checks)
            Assert.Contains($"id=\"chk-{check.Id}\"", html);
    }

    [Fact]
    public void Html_Report_Heading_Order_Never_Skips_A_Level()
    {
        var (checks, env) = CreateTestData();
        checks[0].Status = CheckStatus.Fail;
        var html = HtmlReportGenerator.Generate(checks, env, 50, "F", 30, "F", 20, "F");

        var levels = HeadingRegex().Matches(html)
            .Select(m => int.Parse(m.Groups["level"].Value, CultureInfo.InvariantCulture))
            .ToList();

        Assert.NotEmpty(levels);
        Assert.Equal(1, levels[0]);
        for (var i = 1; i < levels.Count; i++)
            Assert.True(levels[i] <= levels[i - 1] + 1, $"Heading level jumped from h{levels[i - 1]} to h{levels[i]} at position {i}.");
    }

    [Fact]
    public void Html_Report_Table_Headers_All_Declare_Scope()
    {
        var (checks, env) = CreateTestData();
        checks[0].Status = CheckStatus.Fail;
        var html = HtmlReportGenerator.Generate(checks, env, 50, "F", 30, "F", 20, "F");

        var headerCells = ThRegex().Matches(html).Select(m => m.Value).ToList();
        Assert.NotEmpty(headerCells);
        Assert.All(headerCells, th => Assert.Contains("scope=", th, StringComparison.Ordinal));
    }

    [Fact]
    public void Html_Report_Has_Focus_Visible_And_Reduced_Motion_Styles()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C");

        Assert.Contains(":focus-visible", html);
        Assert.Contains("prefers-reduced-motion", html);
        Assert.Contains("thead th { position: sticky", html);
    }

    [Fact]
    public void Html_Report_Toc_Links_Meet_Wcag_Target_Size()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C");

        Assert.Contains("min-height: 24px; min-width: 24px", html);
    }

    [Fact]
    public void Html_Report_Has_Status_Legend_And_Limitations_Naming_Skipped_And_Manual_Checks()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        var automated = CheckItemViewModel.FromMetadata(CheckCatalog.All["EP01"]);
        automated.Status = CheckStatus.NotAssessed;
        checks.Add(automated);
        var manualMeta = CheckCatalog.All.Values.First(m => m.EvidenceMode is EvidenceMode.Checklist or EvidenceMode.InterviewRequired or EvidenceMode.ExternalRequired);
        var manual = CheckItemViewModel.FromMetadata(manualMeta);
        manual.Status = CheckStatus.NotAssessed;
        checks.Add(manual);

        var env = new EnvironmentInfo { ComputerName = "TESTPC", OSCaption = "Windows 11" };
        var html = HtmlReportGenerator.Generate(checks, env, 0, "F", 0, "F");

        Assert.Contains("Status Legend", html);
        Assert.Contains("meets requirements", html);
        Assert.Contains("partially compliant", html);
        Assert.Contains("check(s) require manual evidence", html);
        Assert.Contains("<h2 id=\"scan-limitations\">Limitations</h2>", html);
    }

    [Fact]
    public void Html_Report_Key_Color_Pairs_Meet_Contrast_Targets()
    {
        // Skip link: white text on a near-black chip.
        Assert.True(Contrast(Parse("#f8fafc"), Parse("#11131c")) >= 4.5);
        // TOC link text on the report's card background.
        Assert.True(Contrast(Parse("#89b4fa"), Parse("#313244")) >= 4.5);
        // Body text on the card background used for the status legend.
        Assert.True(Contrast(Parse("#cdd6f4"), Parse("#313244")) >= 4.5);
        // Focus ring color against the dark report background.
        Assert.True(Contrast(Parse("#38bdf8"), Parse("#1e1e2e")) >= 3.0);
    }

    [Fact]
    public void Cmmc_Report_Has_Skip_Link_Landmarks_Focus_And_Reduced_Motion_Styles()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(3))
            checks.Add(CheckItemViewModel.FromMetadata(meta));
        var env = new EnvironmentInfo { ComputerName = "TEST", IsDomainJoined = true, DomainName = "TEST.LOCAL" };

        var html = CmmcReportGenerator.ExportHtml(checks, env, 85, "B");

        Assert.Contains("<a href=\"#main-content\" class=\"skip-link\">Skip to main content</a>", html);
        Assert.Contains("<header class=\"header\">", html);
        Assert.Contains("<main id=\"main-content\">", html);
        Assert.Contains("<footer class=\"footer\">", html);
        Assert.Contains(":focus-visible", html);
        Assert.Contains("prefers-reduced-motion", html);
        var headerCells = ThRegex().Matches(html).Select(m => m.Value).ToList();
        Assert.NotEmpty(headerCells);
        Assert.All(headerCells, th => Assert.Contains("scope=", th, StringComparison.Ordinal));
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

    [GeneratedRegex("<h(?<level>[1-6])[ >]")]
    private static partial Regex HeadingRegex();

    [GeneratedRegex("<th\\b[^>]*>")]
    private static partial Regex ThRegex();

    [GeneratedRegex("<a href=\"#(?<id>[a-z0-9-]+)\">")]
    private static partial Regex TocHrefRegex();
}

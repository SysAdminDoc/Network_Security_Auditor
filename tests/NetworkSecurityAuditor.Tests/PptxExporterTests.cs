using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Validation;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;
using A = DocumentFormat.OpenXml.Drawing;

namespace NetworkSecurityAuditor.Tests;

public class PptxExporterTests
{
    // A 1x1 transparent PNG, valid base64, matching the same "raw base64, no data-uri prefix"
    // convention BrandingConfig.LogoBase64 uses everywhere else in this codebase.
    private const string OnePixelPngBase64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    [Fact]
    public void Build_Produces_A_Package_That_Passes_Open_Xml_Validation()
    {
        using var stream = new MemoryStream();
        PptxExporter.Build(stream, CreateChecks(), CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var validator = new OpenXmlValidator();
        var errors = validator.Validate(document).ToList();

        Assert.Empty(errors);
    }

    [Fact]
    public void Build_Creates_Six_Slides_In_The_Documented_Order()
    {
        using var stream = new MemoryStream();
        PptxExporter.Build(stream, CreateChecks(), CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var slideTexts = SlideTexts(document);

        Assert.Equal(6, slideTexts.Count);
        Assert.Contains("Executive Security Assessment", slideTexts[0]);
        Assert.Contains("Security Posture", slideTexts[1]);
        Assert.Contains("Top 5 Risks", slideTexts[2]);
        Assert.Contains("Compliance Gaps", slideTexts[3]);
        Assert.Contains("Phased Remediation", slideTexts[4]);
        Assert.Contains("Tool Version and Scan Limitations", slideTexts[5]);
    }

    [Fact]
    public void Title_Slide_Shows_Branding_Company_Tagline_Contact_And_Logo()
    {
        var branding = new BrandingConfig
        {
            CompanyName = "Acme Security",
            Tagline = "Protecting what matters",
            ContactName = "Jordan Rivera",
            ContactEmail = "jordan@acme.example",
            LogoBase64 = OnePixelPngBase64
        };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, CreateChecks(), CreateEnv(), 82, "B", 61, "D", branding);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var titleSlidePart = document.PresentationPart!.SlideParts.First();
        var text = ExtractText(titleSlidePart);

        Assert.Contains("Acme Security", text);
        Assert.Contains("Protecting what matters", text);
        Assert.Contains("Jordan Rivera", text);
        Assert.Contains("jordan@acme.example", text);
        Assert.Single(titleSlidePart.ImageParts);
    }

    [Fact]
    public void Title_Slide_Without_Branding_Falls_Back_To_Tool_Name_And_Has_No_Logo()
    {
        using var stream = new MemoryStream();
        PptxExporter.Build(stream, CreateChecks(), CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var titleSlidePart = document.PresentationPart!.SlideParts.First();

        Assert.Contains("Network Security Auditor", ExtractText(titleSlidePart));
        Assert.Empty(titleSlidePart.ImageParts);
    }

    [Fact]
    public void Scores_Slide_Shows_Overall_And_Ransomware_Scores()
    {
        using var stream = new MemoryStream();
        PptxExporter.Build(stream, CreateChecks(), CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var text = SlideTexts(document)[1];

        Assert.Contains("82 (B)", text);
        Assert.Contains("61 (D)", text);
    }

    [Fact]
    public void Top_Risks_Slide_Lists_At_Most_Five_Ordered_By_Severity_Then_Status()
    {
        var checks = new List<CheckItemViewModel>
        {
            Check("LOW1", Severity.Low, CheckStatus.Fail),
            Check("MED1", Severity.Medium, CheckStatus.Fail),
            Check("HIGH1", Severity.High, CheckStatus.Fail),
            Check("HIGH2", Severity.High, CheckStatus.Partial),
            Check("CRIT1", Severity.Critical, CheckStatus.Partial),
            Check("CRIT2", Severity.Critical, CheckStatus.Fail),
            Check("PASS1", Severity.Critical, CheckStatus.Pass), // scored but not a risk
        };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, checks, CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var text = SlideTexts(document)[2];

        Assert.Contains("CRIT1", text);
        Assert.Contains("CRIT2", text);
        Assert.Contains("HIGH1", text);
        Assert.Contains("HIGH2", text);
        Assert.Contains("MED1", text);
        Assert.DoesNotContain("LOW1", text); // sixth by severity, cut by the top-5 limit
        Assert.DoesNotContain("PASS1", text); // passing checks are not risks
    }

    [Fact]
    public void Top_Risks_Slide_States_When_There_Are_No_Open_Findings()
    {
        var checks = new List<CheckItemViewModel> { Check("OK1", Severity.Critical, CheckStatus.Pass) };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, checks, CreateEnv(), 100, "A", 100, "A", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        Assert.Contains("No open Fail or Partial findings.", SlideTexts(document)[2]);
    }

    [Fact]
    public void Compliance_Gaps_Slide_Lists_Frameworks_Below_Eighty_Percent()
    {
        // IA01 is mapped to CIS, NIST, CMMC, HIPAA, PCI, SOC2, ISO27001 and FedRAMP; failing it alone
        // is enough to put every one of those frameworks at 0% and onto the gap list.
        var checks = new List<CheckItemViewModel> { Check("IA01", Severity.High, CheckStatus.Fail) };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, checks, CreateEnv(), 40, "F", 40, "F", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var text = SlideTexts(document)[3];

        Assert.Contains("NIST 800-171: 0% ready", text);
    }

    [Fact]
    public void Compliance_Gaps_Slide_States_When_Nothing_Is_Below_Threshold()
    {
        using var stream = new MemoryStream();
        PptxExporter.Build(stream, new List<CheckItemViewModel>(), CreateEnv(), 100, "A", 100, "A", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        Assert.Contains("No framework is below 80% readiness.", SlideTexts(document)[3]);
    }

    [Fact]
    public void Phased_Remediation_Slide_Uses_The_Ps1_Reports_Phase_Wording()
    {
        var checks = new List<CheckItemViewModel>
        {
            Check("C1", Severity.Critical, CheckStatus.Fail),
            Check("H1", Severity.High, CheckStatus.Fail),
            Check("M1", Severity.Medium, CheckStatus.Partial),
            Check("L1", Severity.Low, CheckStatus.Fail), // Low never appears in the PS1 roadmap phases
        };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, checks, CreateEnv(), 60, "D", 60, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var text = SlideTexts(document)[4];

        Assert.Contains("Phase 1: Immediate (0-7 days) - 1 items", text);
        Assert.Contains("Phase 2: Short-term (8-30 days) - 1 items", text);
        Assert.Contains("Phase 3: Medium-term (30-90 days) - 1 items", text);
    }

    [Fact]
    public void Limitations_Slide_Shows_Tool_Version_And_Coverage_Gaps()
    {
        var checks = new List<CheckItemViewModel>
        {
            Check("A1", Severity.Medium, CheckStatus.Pass),
            Check("A2", Severity.Medium, CheckStatus.NotAssessed),
            Check("A3", Severity.Medium, CheckStatus.Error),
        };

        using var stream = new MemoryStream();
        PptxExporter.Build(stream, checks, CreateEnv(), 82, "B", 61, "D", null);

        stream.Position = 0;
        using var document = PresentationDocument.Open(stream, false);
        var text = SlideTexts(document)[5];

        Assert.Contains($"Network Security Auditor v{VersionInfo.Version}", text);
        Assert.Contains("1 checks require manual review", text);
        Assert.Contains("1 checks errored", text);
    }

    [Theory]
    [InlineData("#abc", "AABBCC")]
    [InlineData("#cba6f7", "CBA6F7")]
    [InlineData("#cba6f7ff", "CBA6F7")]
    [InlineData("rgb(203, 166, 247)", "CBA6F7")]
    [InlineData("notacolor", "CBA6F7")]
    [InlineData("", "CBA6F7")]
    public void NormalizeHex_Reduces_Any_Safe_Branding_Color_To_Plain_Rrggbb(string input, string expected)
    {
        Assert.Equal(expected, PptxExporter.NormalizeHex(input));
    }

    [Fact]
    public async Task ExportAsync_Writes_A_Valid_Package_To_Disk_Atomically()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nsa-pptx-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "report.pptx");
        try
        {
            var (success, message) = await PptxExporter.ExportAsync(path, CreateChecks(), CreateEnv(), 82, "B", 61, "D", null);

            Assert.True(success, message);
            Assert.Equal(path, message);
            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 0);
            Assert.Empty(Directory.GetFiles(dir, "*.tmp.pptx")); // no leftover temp file

            using var document = PresentationDocument.Open(path, false);
            Assert.Equal(6, document.PresentationPart!.SlideParts.Count());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static List<string> SlideTexts(PresentationDocument document) =>
        document.PresentationPart!.SlideParts.Select(ExtractText).ToList();

    private static string ExtractText(SlidePart part) =>
        string.Join("\n", part.Slide!.Descendants<A.Text>().Select(t => t.Text));

    private static CheckItemViewModel Check(string id, Severity severity, CheckStatus status) => new()
    {
        Id = id,
        Label = $"Check {id}",
        Category = "Category",
        Severity = severity,
        Status = status
    };

    private static List<CheckItemViewModel> CreateChecks() =>
    [
        Check("EP01", Severity.High, CheckStatus.Fail),
        Check("EP02", Severity.Medium, CheckStatus.Pass),
    ];

    private static EnvironmentInfo CreateEnv() => new() { ComputerName = "TESTPC", OSCaption = "Windows 11" };
}

using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.Theme;
using NetworkSecurityAuditor.ViewModels;
using A = DocumentFormat.OpenXml.Drawing;
using P = DocumentFormat.OpenXml.Presentation;

namespace NetworkSecurityAuditor.Export;

/// <summary>
/// Builds a one-scan executive PowerPoint deck (title, scores, top risks, compliance gaps, phased
/// remediation, version/limitations) as a minimal but schema-valid Open XML package. No placeholders
/// are used; every slide draws its own absolutely-positioned text boxes against a blank master/layout,
/// which keeps the object model small while still opening cleanly in PowerPoint and LibreOffice.
/// </summary>
public static partial class PptxExporter
{
    private const long SlideWidth = 12192000L;
    private const long SlideHeight = 6858000L;
    private const long Margin = 457200L;

    public static async Task<(bool Success, string Message)> ExportAsync(
        string pptxPath,
        IReadOnlyList<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int score,
        string grade,
        int rwScore,
        string rwGrade,
        BrandingConfig? branding)
    {
        var targetPath = Path.GetFullPath(pptxPath);
        var targetDirectory = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrWhiteSpace(targetDirectory))
            Directory.CreateDirectory(targetDirectory);

        var tempPath = Path.Combine(
            targetDirectory ?? Path.GetTempPath(),
            $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp.pptx");

        try
        {
            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.ReadWrite))
                Build(stream, checks, env, score, grade, rwScore, rwGrade, branding);

            if (!File.Exists(tempPath) || new FileInfo(tempPath).Length == 0)
                return (false, "PPTX generation produced an empty file.");

            File.Move(tempPath, targetPath, overwrite: true);
            return (true, targetPath);
        }
        catch (Exception ex)
        {
            return (false, $"PPTX export failed: {ex.Message}");
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch
            {
                // Best-effort cleanup; preserve the original export result.
            }
        }
    }

    /// <summary>
    /// Builds the package straight onto the caller's stream. Public entry point for the exporter and for
    /// tests that validate the package with <see cref="DocumentFormat.OpenXml.Validation.OpenXmlValidator"/>
    /// without ever writing to disk or launching PowerPoint.
    /// </summary>
    internal static void Build(
        Stream stream,
        IReadOnlyList<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int score,
        string grade,
        int rwScore,
        string rwGrade,
        BrandingConfig? branding)
    {
        using var document = PresentationDocument.Create(stream, DocumentFormat.OpenXml.PresentationDocumentType.Presentation);
        var presentationPart = document.AddPresentationPart();
        presentationPart.Presentation = new P.Presentation();

        var primaryHex = NormalizeHex(branding?.EffectivePrimary ?? "#cba6f7");
        var accentHex = NormalizeHex(branding?.EffectiveAccent ?? "#89b4fa");

        var slideMasterPart = presentationPart.AddNewPart<SlideMasterPart>();
        var slideLayoutPart = slideMasterPart.AddNewPart<SlideLayoutPart>();
        var themePart = slideMasterPart.AddNewPart<ThemePart>();

        themePart.Theme = BuildTheme(primaryHex, accentHex);
        themePart.Theme.Save();

        slideLayoutPart.SlideLayout = BuildBlankLayout();
        slideLayoutPart.SlideLayout.Save();

        slideMasterPart.SlideMaster = BuildSlideMaster(slideMasterPart.GetIdOfPart(slideLayoutPart));
        slideMasterPart.SlideMaster.Save();

        presentationPart.Presentation.Append(new P.SlideMasterIdList(new P.SlideMasterId
        {
            Id = 2147483648U,
            RelationshipId = presentationPart.GetIdOfPart(slideMasterPart)
        }));

        var slideIdList = new P.SlideIdList();
        presentationPart.Presentation.Append(slideIdList);
        presentationPart.Presentation.Append(new P.SlideSize { Cx = (int)SlideWidth, Cy = (int)SlideHeight, Type = P.SlideSizeValues.Screen16x9 });
        presentationPart.Presentation.Append(new P.NotesSize { Cx = 6858000, Cy = 9144000 });

        uint slideId = 256;

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            slidePart => BuildTitleSlideShapes(slidePart, env, branding, primaryHex));

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            _ => BuildScoresSlideShapes(score, grade, rwScore, rwGrade));

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            _ => BuildTopRisksSlideShapes(checks));

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            _ => BuildComplianceGapsSlideShapes(checks));

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            _ => BuildPhasedRemediationSlideShapes(checks));

        AddSlide(presentationPart, slideLayoutPart, slideIdList, ref slideId,
            _ => BuildLimitationsSlideShapes(checks));

        presentationPart.Presentation.Save();
    }

    private static void AddSlide(
        PresentationPart presentationPart,
        SlideLayoutPart layoutPart,
        P.SlideIdList slideIdList,
        ref uint slideId,
        Func<SlidePart, IEnumerable<OpenXmlElement>> buildShapes)
    {
        var slidePart = presentationPart.AddNewPart<SlidePart>();
        slidePart.AddPart(layoutPart);

        var shapeTree = EmptyShapeTree();
        foreach (var shape in buildShapes(slidePart))
            shapeTree.Append(shape);

        slidePart.Slide = new P.Slide(new P.CommonSlideData(shapeTree));
        slidePart.Slide.Save();

        slideIdList.Append(new P.SlideId { Id = slideId, RelationshipId = presentationPart.GetIdOfPart(slidePart) });
        slideId++;
    }

    // ---------------------------------------------------------------------
    // Slide content
    // ---------------------------------------------------------------------

    private static List<OpenXmlElement> BuildTitleSlideShapes(
        SlidePart slidePart, EnvironmentInfo env, BrandingConfig? branding, string primaryHex)
    {
        var shapes = new List<OpenXmlElement>();
        uint id = 2;

        shapes.Add(ColorBand(id++, 0, 0, SlideWidth, 1371600, primaryHex));

        var logoBytes = branding is { HasLogo: true } ? TryDecodeLogo(branding.LogoBase64) : null;
        var hasLogo = logoBytes is not null;
        var titleX = hasLogo ? 1600200L : Margin;

        if (hasLogo)
        {
            var imagePart = slidePart.AddImagePart(ImagePartType.Png);
            using (var imageStream = new MemoryStream(logoBytes!))
                imagePart.FeedData(imageStream);

            shapes.Add(LogoPicture(id++, slidePart.GetIdOfPart(imagePart), Margin, 228600, 914400, 914400));
        }

        var companyLine = string.IsNullOrWhiteSpace(branding?.CompanyName)
            ? "Network Security Auditor"
            : branding!.CompanyName;
        shapes.Add(TextBox(id++, "Company", titleX, 320040, SlideWidth - titleX - Margin, 731520,
            A.TextAlignmentTypeValues.Left,
            new SlideLine(companyLine, 2800, true, "FFFFFF")));

        shapes.Add(TextBox(id++, "Title", Margin, 1600200, SlideWidth - 2 * Margin, 731520,
            A.TextAlignmentTypeValues.Left,
            new SlideLine("Executive Security Assessment", 4000, true, "1E1E2E")));

        var metaLines = new List<SlideLine>();
        if (!string.IsNullOrWhiteSpace(branding?.Tagline))
            metaLines.Add(new SlideLine(branding!.Tagline, 1800, false, "45475A"));
        var host = string.IsNullOrWhiteSpace(env.ComputerName) ? "Unknown host" : env.ComputerName;
        var os = string.IsNullOrWhiteSpace(env.OSCaption) ? "" : $" ({env.OSCaption})";
        metaLines.Add(new SlideLine($"{host}{os}", 1600, false, "45475A"));
        metaLines.Add(new SlideLine(DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), 1600, false, "45475A"));
        shapes.Add(TextBox(id++, "Meta", Margin, 2514600, SlideWidth - 2 * Margin, 1600200,
            A.TextAlignmentTypeValues.Left, metaLines.ToArray()));

        var contactParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(branding?.ContactName)) contactParts.Add(branding!.ContactName);
        if (!string.IsNullOrWhiteSpace(branding?.ContactEmail)) contactParts.Add(branding!.ContactEmail);
        if (!string.IsNullOrWhiteSpace(branding?.ContactPhone)) contactParts.Add(branding!.ContactPhone);
        var contactLine = string.Join("  |  ", contactParts);
        var footerLine = branding?.FooterText ?? "";
        var footerText = string.Join("   ", new[] { contactLine, footerLine }.Where(s => !string.IsNullOrWhiteSpace(s)));
        if (!string.IsNullOrWhiteSpace(footerText))
        {
            shapes.Add(TextBox(id++, "Contact", Margin, SlideHeight - 685800, SlideWidth - 2 * Margin, 457200,
                A.TextAlignmentTypeValues.Left,
                new SlideLine(footerText, 1200, false, "6C7086")));
        }

        return shapes;
    }

    private static List<OpenXmlElement> BuildScoresSlideShapes(int score, string grade, int rwScore, string rwGrade)
    {
        var shapes = new List<OpenXmlElement>
        {
            TitleBar(2, "Security Posture")
        };

        shapes.Add(TextBox(3, "OverallLabel", Margin, 1828800, 5486400, 457200,
            A.TextAlignmentTypeValues.Left, new SlideLine("Overall Score", 2000, false, "1E1E2E")));
        shapes.Add(TextBox(4, "OverallValue", Margin, 2286000, 5486400, 1143000,
            A.TextAlignmentTypeValues.Left, new SlideLine($"{score} ({grade})", 5400, true, GradeHex(grade))));

        shapes.Add(TextBox(5, "RansomwareLabel", 6400800, 1828800, 5486400, 457200,
            A.TextAlignmentTypeValues.Left, new SlideLine("Ransomware Readiness", 2000, false, "1E1E2E")));
        shapes.Add(TextBox(6, "RansomwareValue", 6400800, 2286000, 5486400, 1143000,
            A.TextAlignmentTypeValues.Left, new SlideLine($"{rwScore} ({rwGrade})", 5400, true, GradeHex(rwGrade))));

        return shapes;
    }

    private static List<OpenXmlElement> BuildTopRisksSlideShapes(IReadOnlyList<CheckItemViewModel> checks)
    {
        var shapes = new List<OpenXmlElement> { TitleBar(2, "Top 5 Risks") };

        var risks = checks
            .Where(c => c.Status is CheckStatus.Fail or CheckStatus.Partial)
            .OrderByDescending(c => c.Severity)
            .ThenByDescending(c => c.Status)
            .ThenBy(c => c.Category, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToList();

        var lines = risks.Count == 0
            ? [new SlideLine("No open Fail or Partial findings.", 1800, false, "1E1E2E")]
            : risks.Select(c => new SlideLine(
                $"{c.Id}: {c.Label} ({SeverityLabel(c.Severity)}, {c.Status})", 1800, false, "1E1E2E", Bullet: true)).ToArray();

        shapes.Add(TextBox(3, "Risks", Margin, 1828800, SlideWidth - 2 * Margin, 4114800,
            A.TextAlignmentTypeValues.Left, lines));

        return shapes;
    }

    private static List<OpenXmlElement> BuildComplianceGapsSlideShapes(IReadOnlyList<CheckItemViewModel> checks)
    {
        var shapes = new List<OpenXmlElement> { TitleBar(2, "Compliance Gaps") };

        var statusLookup = checks.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);
        var gaps = new List<(string Name, double Pct)>();
        foreach (var (fwName, sel) in FrameworkDefinitions.All)
        {
            var mapped = FrameworkMappings.All.Where(kv => sel(kv.Value) is not null).Select(kv => kv.Key).ToList();
            int assessed = 0, met = 0;
            foreach (var cid in mapped)
            {
                if (!statusLookup.TryGetValue(cid, out var st) || !st.IsScored())
                    continue;
                assessed++;
                if (st == CheckStatus.Pass) met++;
            }
            var pct = assessed > 0 ? Math.Round((double)met / assessed * 100, 1) : 0;
            if (assessed > 0 && pct < 80)
                gaps.Add((fwName, pct));
        }

        var worst = gaps.OrderBy(g => g.Pct).Take(5).ToList();
        var lines = worst.Count == 0
            ? [new SlideLine("No framework is below 80% readiness.", 1800, false, "1E1E2E")]
            : worst.Select(g => new SlideLine(
                $"{g.Name}: {g.Pct.ToString(CultureInfo.InvariantCulture)}% ready", 1800, false, "1E1E2E", Bullet: true)).ToArray();

        shapes.Add(TextBox(3, "Gaps", Margin, 1828800, SlideWidth - 2 * Margin, 4114800,
            A.TextAlignmentTypeValues.Left, lines));

        return shapes;
    }

    private static List<OpenXmlElement> BuildPhasedRemediationSlideShapes(IReadOnlyList<CheckItemViewModel> checks)
    {
        var shapes = new List<OpenXmlElement> { TitleBar(2, "Phased Remediation") };

        var open = checks.Where(c => c.Status is CheckStatus.Fail or CheckStatus.Partial).ToList();
        var critical = open.Count(c => c.Severity == Severity.Critical);
        var high = open.Count(c => c.Severity == Severity.High);
        var medium = open.Count(c => c.Severity == Severity.Medium);

        var lines = new List<SlideLine>();
        if (critical > 0) lines.Add(new SlideLine($"Phase 1: Immediate (0-7 days) - {critical} items", 2000, false, DesignTokens.SeverityCriticalHex.TrimStart('#'), Bullet: true));
        if (high > 0) lines.Add(new SlideLine($"Phase 2: Short-term (8-30 days) - {high} items", 2000, false, DesignTokens.SeverityHighHex.TrimStart('#'), Bullet: true));
        if (medium > 0) lines.Add(new SlideLine($"Phase 3: Medium-term (30-90 days) - {medium} items", 2000, false, DesignTokens.SeverityMediumHex.TrimStart('#'), Bullet: true));
        if (lines.Count == 0) lines.Add(new SlideLine("No open findings require remediation.", 1800, false, "1E1E2E"));

        shapes.Add(TextBox(3, "Phases", Margin, 1828800, SlideWidth - 2 * Margin, 4114800,
            A.TextAlignmentTypeValues.Left, lines.ToArray()));

        return shapes;
    }

    private static List<OpenXmlElement> BuildLimitationsSlideShapes(IReadOnlyList<CheckItemViewModel> checks)
    {
        var shapes = new List<OpenXmlElement> { TitleBar(2, "Tool Version and Scan Limitations") };

        var coverage = CoverageSummary.From(checks);
        var lines = new List<SlideLine>
        {
            new($"Network Security Auditor v{VersionInfo.Version}", 2000, true, "1E1E2E"),
            new($"Scored {coverage.Scored} of {coverage.Applicable} applicable checks ({coverage.Pct.ToString(CultureInfo.InvariantCulture)}%)", 1800, false, "1E1E2E", Bullet: true),
        };
        if (coverage.NotAssessed > 0)
            lines.Add(new SlideLine($"{coverage.NotAssessed} checks require manual review", 1800, false, "1E1E2E", Bullet: true));
        if (coverage.Errors > 0)
            lines.Add(new SlideLine($"{coverage.Errors} checks errored ({coverage.TimedOut} timed out)", 1800, false, "1E1E2E", Bullet: true));
        if (coverage.NotApplicable > 0)
            lines.Add(new SlideLine($"{coverage.NotApplicable} checks not applicable to this environment", 1800, false, "1E1E2E", Bullet: true));

        shapes.Add(TextBox(3, "Limitations", Margin, 1828800, SlideWidth - 2 * Margin, 4114800,
            A.TextAlignmentTypeValues.Left, lines.ToArray()));

        return shapes;
    }

    // ---------------------------------------------------------------------
    // Shape builders
    // ---------------------------------------------------------------------

    private readonly record struct SlideLine(string Text, int SizeHundredths, bool Bold, string? ColorHex, bool Bullet = false);

    private static P.Shape TitleBar(uint id, string title) =>
        TextBox(id, "SlideTitle", Margin, 274638, SlideWidth - 2 * Margin, 914400,
            A.TextAlignmentTypeValues.Left, new SlideLine(title, 3200, true, "1E1E2E"));

    private static P.Shape TextBox(uint id, string name, long x, long y, long cx, long cy,
        A.TextAlignmentTypeValues align, params SlideLine[] lines)
    {
        var textBody = new P.TextBody(
            new A.BodyProperties { Wrap = A.TextWrappingValues.Square, Anchor = A.TextAnchoringTypeValues.Top },
            new A.ListStyle());

        foreach (var line in lines)
        {
            var paragraph = new A.Paragraph();
            var pPr = new A.ParagraphProperties { Alignment = align };
            if (line.Bullet)
            {
                pPr.LeftMargin = 228600;
                pPr.Indent = -228600;
                pPr.Append(new A.CharacterBullet { Char = "•" });
            }
            else
            {
                pPr.Append(new A.NoBullet());
            }
            paragraph.Append(pPr);

            var runProps = new A.RunProperties { FontSize = line.SizeHundredths, Bold = line.Bold, Language = "en-US" };
            if (line.ColorHex is not null)
                runProps.Append(new A.SolidFill(new A.RgbColorModelHex { Val = line.ColorHex.TrimStart('#').ToUpperInvariant() }));
            paragraph.Append(new A.Run(runProps, new A.Text(line.Text)));

            textBody.Append(paragraph);
        }

        return new P.Shape(
            new P.NonVisualShapeProperties(
                new P.NonVisualDrawingProperties { Id = id, Name = name },
                new P.NonVisualShapeDrawingProperties(new A.ShapeLocks { NoGrouping = true }),
                new P.ApplicationNonVisualDrawingProperties()),
            new P.ShapeProperties(
                new A.Transform2D(new A.Offset { X = x, Y = y }, new A.Extents { Cx = cx, Cy = cy }),
                new A.PresetGeometry(new A.AdjustValueList()) { Preset = A.ShapeTypeValues.Rectangle }),
            textBody);
    }

    private static P.Shape ColorBand(uint id, long x, long y, long cx, long cy, string hex) =>
        new(
            new P.NonVisualShapeProperties(
                new P.NonVisualDrawingProperties { Id = id, Name = "Accent Band" },
                new P.NonVisualShapeDrawingProperties(new A.ShapeLocks { NoGrouping = true }),
                new P.ApplicationNonVisualDrawingProperties()),
            new P.ShapeProperties(
                new A.Transform2D(new A.Offset { X = x, Y = y }, new A.Extents { Cx = cx, Cy = cy }),
                new A.PresetGeometry(new A.AdjustValueList()) { Preset = A.ShapeTypeValues.Rectangle },
                new A.SolidFill(new A.RgbColorModelHex { Val = hex.TrimStart('#').ToUpperInvariant() }),
                new A.Outline(new A.NoFill())));

    private static P.Picture LogoPicture(uint id, string embedRelationshipId, long x, long y, long cx, long cy) =>
        new(
            new P.NonVisualPictureProperties(
                new P.NonVisualDrawingProperties { Id = id, Name = "Logo" },
                new P.NonVisualPictureDrawingProperties(),
                new P.ApplicationNonVisualDrawingProperties()),
            new P.BlipFill(
                new A.Blip { Embed = embedRelationshipId },
                new A.Stretch(new A.FillRectangle())),
            new P.ShapeProperties(
                new A.Transform2D(new A.Offset { X = x, Y = y }, new A.Extents { Cx = cx, Cy = cy }),
                new A.PresetGeometry(new A.AdjustValueList()) { Preset = A.ShapeTypeValues.Rectangle }));

    private static byte[]? TryDecodeLogo(string base64)
    {
        try
        {
            return string.IsNullOrWhiteSpace(base64) ? null : Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Master / layout / theme scaffolding
    // ---------------------------------------------------------------------

    private static P.ShapeTree EmptyShapeTree() =>
        new(
            new P.NonVisualGroupShapeProperties(
                new P.NonVisualDrawingProperties { Id = 1, Name = "" },
                new P.NonVisualGroupShapeDrawingProperties(),
                new P.ApplicationNonVisualDrawingProperties()),
            new P.GroupShapeProperties(new A.TransformGroup(
                new A.Offset { X = 0, Y = 0 },
                new A.Extents { Cx = 0, Cy = 0 },
                new A.ChildOffset { X = 0, Y = 0 },
                new A.ChildExtents { Cx = 0, Cy = 0 })));

    private static P.SlideLayout BuildBlankLayout() =>
        new(
            new P.CommonSlideData(EmptyShapeTree()),
            new P.ColorMapOverride(new A.MasterColorMapping()))
        {
            Type = P.SlideLayoutValues.Blank
        };

    private static P.SlideMaster BuildSlideMaster(string layoutRelationshipId) =>
        new(
            new P.CommonSlideData(EmptyShapeTree()),
            new P.ColorMap
            {
                Background1 = A.ColorSchemeIndexValues.Light1,
                Text1 = A.ColorSchemeIndexValues.Dark1,
                Background2 = A.ColorSchemeIndexValues.Light2,
                Text2 = A.ColorSchemeIndexValues.Dark2,
                Accent1 = A.ColorSchemeIndexValues.Accent1,
                Accent2 = A.ColorSchemeIndexValues.Accent2,
                Accent3 = A.ColorSchemeIndexValues.Accent3,
                Accent4 = A.ColorSchemeIndexValues.Accent4,
                Accent5 = A.ColorSchemeIndexValues.Accent5,
                Accent6 = A.ColorSchemeIndexValues.Accent6,
                Hyperlink = A.ColorSchemeIndexValues.Hyperlink,
                FollowedHyperlink = A.ColorSchemeIndexValues.FollowedHyperlink
            },
            new P.SlideLayoutIdList(new P.SlideLayoutId { Id = 2147483649U, RelationshipId = layoutRelationshipId }));

    private static A.Theme BuildTheme(string accent1Hex, string accent2Hex)
    {
        var theme = new A.Theme { Name = "NSA Executive Theme" };

        var themeElements = new A.ThemeElements(
            new A.ColorScheme(
                new A.Dark1Color(new A.SystemColor { Val = A.SystemColorValues.WindowText, LastColor = "000000" }),
                new A.Light1Color(new A.SystemColor { Val = A.SystemColorValues.Window, LastColor = "FFFFFF" }),
                new A.Dark2Color(new A.RgbColorModelHex { Val = "1F1F1F" }),
                new A.Light2Color(new A.RgbColorModelHex { Val = "EEECE1" }),
                new A.Accent1Color(new A.RgbColorModelHex { Val = accent1Hex }),
                new A.Accent2Color(new A.RgbColorModelHex { Val = accent2Hex }),
                new A.Accent3Color(new A.RgbColorModelHex { Val = "9BBB59" }),
                new A.Accent4Color(new A.RgbColorModelHex { Val = "8064A2" }),
                new A.Accent5Color(new A.RgbColorModelHex { Val = "4BACC6" }),
                new A.Accent6Color(new A.RgbColorModelHex { Val = "F79646" }),
                new A.Hyperlink(new A.RgbColorModelHex { Val = "0563C1" }),
                new A.FollowedHyperlinkColor(new A.RgbColorModelHex { Val = "954F72" }))
            {
                Name = "NSA"
            },
            new A.FontScheme(
                new A.MajorFont(
                    new A.LatinFont { Typeface = "Calibri" },
                    new A.EastAsianFont { Typeface = "" },
                    new A.ComplexScriptFont { Typeface = "" }),
                new A.MinorFont(
                    new A.LatinFont { Typeface = "Calibri" },
                    new A.EastAsianFont { Typeface = "" },
                    new A.ComplexScriptFont { Typeface = "" }))
            {
                Name = "NSA"
            },
            new A.FormatScheme(
                new A.FillStyleList(
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Accent1 }),
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Accent1 }),
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Accent1 })),
                new A.LineStyleList(
                    new A.Outline(new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Text1 })) { Width = 6350 },
                    new A.Outline(new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Text1 })) { Width = 12700 },
                    new A.Outline(new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Text1 })) { Width = 19050 }),
                new A.EffectStyleList(
                    new A.EffectStyle(new A.EffectList()),
                    new A.EffectStyle(new A.EffectList()),
                    new A.EffectStyle(new A.EffectList())),
                new A.BackgroundFillStyleList(
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Light1 }),
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Light1 }),
                    new A.SolidFill(new A.SchemeColor { Val = A.SchemeColorValues.Light1 })))
            {
                Name = "NSA"
            });

        theme.Append(themeElements);
        theme.Append(new A.ObjectDefaults());
        theme.Append(new A.ExtraColorSchemeList());
        return theme;
    }

    // ---------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------

    private static string GradeHex(string grade) => grade switch
    {
        "A" => DesignTokens.GradeAHex,
        "B" => DesignTokens.GradeBHex,
        "C" => DesignTokens.GradeCHex,
        "D" => DesignTokens.GradeDHex,
        _ => DesignTokens.GradeFHex
    };

    private static string SeverityLabel(Severity severity) => severity switch
    {
        Severity.Critical => "Critical",
        Severity.High => "High",
        Severity.Medium => "Medium",
        Severity.Low => "Low",
        _ => "Unknown"
    };

    [GeneratedRegex(@"^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$", RegexOptions.IgnoreCase)]
    private static partial Regex RgbColorPattern();

    /// <summary>
    /// Reduces a branding color (already validated by <see cref="BrandingConfig"/> as 3/6/8-digit hex,
    /// an rgb() triple, or a bare color name) to the plain 6-digit RRGGBB hex the Open XML theme schema
    /// requires. Anything it can't confidently parse falls back to the Catppuccin mauve default rather
    /// than failing the whole export.
    /// </summary>
    internal static string NormalizeHex(string cssColor)
    {
        const string fallback = "CBA6F7";
        if (string.IsNullOrWhiteSpace(cssColor))
            return fallback;

        var value = cssColor.Trim();
        if (value.StartsWith('#'))
        {
            var hex = value[1..];
            return hex.Length switch
            {
                3 => $"{hex[0]}{hex[0]}{hex[1]}{hex[1]}{hex[2]}{hex[2]}".ToUpperInvariant(),
                6 or 8 => hex[..6].ToUpperInvariant(),
                _ => fallback
            };
        }

        var rgbMatch = RgbColorPattern().Match(value);
        if (rgbMatch.Success)
        {
            var r = byte.Parse(rgbMatch.Groups[1].Value, CultureInfo.InvariantCulture);
            var g = byte.Parse(rgbMatch.Groups[2].Value, CultureInfo.InvariantCulture);
            var b = byte.Parse(rgbMatch.Groups[3].Value, CultureInfo.InvariantCulture);
            return $"{r:X2}{g:X2}{b:X2}";
        }

        return fallback;
    }
}

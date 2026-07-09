using System.Globalization;
using System.Text.RegularExpressions;

namespace NetworkSecurityAuditor.Tests;

public sealed partial class ThemeContrastTests
{
    [Theory]
    [InlineData("TextPrimary", "WindowBg", 4.5)]
    [InlineData("TextMuted", "PanelBg", 4.5)]
    [InlineData("ControlBorder", "InputBg", 3.0)]
    [InlineData("ScrollThumb", "PanelBg", 3.0)]
    [InlineData("WindowBg", "Accent", 3.0)]
    public void Theme_Tokens_Meet_Their_Wcag_Contrast_Target(string foreground, string background, double minimum)
    {
        var colors = LoadBrushColors();
        var ratio = Contrast(colors[foreground], colors[background]);

        Assert.True(
            ratio >= minimum,
            $"{foreground} on {background} is {ratio:0.00}:1; expected at least {minimum:0.0}:1.");
    }

    private static Dictionary<string, Rgb> LoadBrushColors()
    {
        var themePath = Path.Combine(FindRepoRoot(), "src", "NetworkSecurityAuditor", "Theme", "Themes.xaml");
        var xaml = File.ReadAllText(themePath);
        return BrushRegex().Matches(xaml).ToDictionary(
            match => match.Groups["key"].Value,
            match => Parse(match.Groups["hex"].Value),
            StringComparer.Ordinal);
    }

    private static Rgb Parse(string value) => new(
        byte.Parse(value.AsSpan(1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
        byte.Parse(value.AsSpan(3, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
        byte.Parse(value.AsSpan(5, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));

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

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
            directory = directory.Parent;

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }

    private readonly record struct Rgb(byte Red, byte Green, byte Blue);

    [GeneratedRegex("<SolidColorBrush\\s+x:Key=\\\"(?<key>[^\\\"]+)\\\"\\s+Color=\\\"(?<hex>#[0-9A-Fa-f]{6})\\\"\\s*/>")]
    private static partial Regex BrushRegex();
}

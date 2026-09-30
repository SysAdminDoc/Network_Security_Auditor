using System.Windows.Media;

namespace NetworkSecurityAuditor.Theme;

/// <summary>
/// Single source of truth for the severity, status and grade colors shown on both the WPF dashboard
/// and the HTML/CMMC report exports. The WPF theme resource dictionaries reference the <c>*Color</c>
/// fields directly through <c>x:Static</c>; the report CSS interpolates the <c>*Hex</c> constants.
/// Change a color here and both surfaces follow, instead of drifting apart the way the dashboard and
/// report CSS used to.
/// </summary>
public static class DesignTokens
{
    public const string SeverityCriticalHex = "#f38ba8";
    public const string SeverityHighHex = "#fab387";
    public const string SeverityMediumHex = "#f9e2af";
    public const string SeverityLowHex = "#a6e3a1";

    public const string StatusPassHex = "#a6e3a1";
    public const string StatusPartialHex = "#f9e2af";
    public const string StatusFailHex = "#f38ba8";
    public const string StatusNaHex = "#9399b2";
    public const string StatusNotAssessedHex = "#585b70";
    public const string StatusErrorHex = "#fab387";

    public const string GradeAHex = "#a6e3a1";
    public const string GradeBHex = "#94e2d5";
    public const string GradeCHex = "#f9e2af";
    public const string GradeDHex = "#fab387";
    public const string GradeFHex = "#f38ba8";

    public static readonly Color SeverityCriticalColor = ParseColor(SeverityCriticalHex);
    public static readonly Color SeverityHighColor = ParseColor(SeverityHighHex);
    public static readonly Color SeverityMediumColor = ParseColor(SeverityMediumHex);
    public static readonly Color SeverityLowColor = ParseColor(SeverityLowHex);

    public static readonly Color StatusPassColor = ParseColor(StatusPassHex);
    public static readonly Color StatusPartialColor = ParseColor(StatusPartialHex);
    public static readonly Color StatusFailColor = ParseColor(StatusFailHex);
    public static readonly Color StatusNaColor = ParseColor(StatusNaHex);
    public static readonly Color StatusNotAssessedColor = ParseColor(StatusNotAssessedHex);
    public static readonly Color StatusErrorColor = ParseColor(StatusErrorHex);

    public static readonly Color GradeAColor = ParseColor(GradeAHex);
    public static readonly Color GradeBColor = ParseColor(GradeBHex);
    public static readonly Color GradeCColor = ParseColor(GradeCHex);
    public static readonly Color GradeDColor = ParseColor(GradeDHex);
    public static readonly Color GradeFColor = ParseColor(GradeFHex);

    private static Color ParseColor(string hex) => (Color)ColorConverter.ConvertFromString(hex)!;
}

using System.Collections.Frozen;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// Category risk weight multipliers for weighted scoring, severity display colors,
/// and per-category accent colors for UI theming.
/// </summary>
public static class CategoryWeights
{
    /// <summary>
    /// Multipliers applied to raw check scores during weighted scoring.
    /// Higher weight = category contributes more to the overall risk score.
    /// </summary>
    public static FrozenDictionary<string, double> Weights { get; } =
        new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
        {
            ["Identity & Access"]    = 1.5,  // Keys to the kingdom
            ["Endpoint Security"]    = 1.2,  // Direct attack surface
            ["Network Perimeter"]    = 1.3,  // External exposure
            ["Logging & Monitoring"] = 1.0,  // Detection capability
            ["Network Architecture"] = 0.9,  // Infrastructure design
            ["Backup & Recovery"]    = 1.1,  // Resilience
            ["Common Findings"]      = 1.0,  // Frequent issues
            ["Physical Security"]    = 0.7,  // Softer controls
            ["Policies & Standards"] = 0.7   // Administrative controls
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>Returns the weight multiplier for a category, defaulting to 1.0 for unknown categories.</summary>
    public static double GetWeight(string category) =>
        Weights.TryGetValue(category, out var w) ? w : 1.0;

    /// <summary>
    /// Hex color codes for severity levels, matching Catppuccin/dark-theme palette.
    /// </summary>
    public static FrozenDictionary<string, string> SeverityColors { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Critical"] = "#f87171",  // Red 400
            ["High"]     = "#f97316",  // Orange 500
            ["Medium"]   = "#eab308",  // Yellow 500
            ["Low"]      = "#22c55e"   // Green 500
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Per-category accent hex colors for UI badges, progress bars, and chart segments.
    /// </summary>
    public static FrozenDictionary<string, string> CategoryAccents { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Network Perimeter"]    = "#0ea5e9",  // Sky 500
            ["Identity & Access"]    = "#a855f7",  // Purple 500
            ["Endpoint Security"]    = "#22c55e",  // Green 500
            ["Backup & Recovery"]    = "#eab308",  // Yellow 500
            ["Logging & Monitoring"] = "#f97316",  // Orange 500
            ["Network Architecture"] = "#06b6d4",  // Cyan 500
            ["Physical Security"]    = "#ec4899",  // Pink 500
            ["Common Findings"]      = "#ef4444",  // Red 500
            ["Policies & Standards"] = "#8b5cf6"   // Violet 500
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>Returns the accent color for a category, defaulting to neutral gray for unknown categories.</summary>
    public static string GetAccent(string category) =>
        CategoryAccents.TryGetValue(category, out var c) ? c : "#94a3b8";
}

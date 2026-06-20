using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace NetworkSecurityAuditor.Models;

public sealed partial class BrandingConfig
{
    public string CompanyName { get; set; } = "";
    public string LogoBase64 { get; set; } = "";
    public string PrimaryColor { get; set; } = "";
    public string AccentColor { get; set; } = "";
    public string ContactName { get; set; } = "";
    public string ContactEmail { get; set; } = "";
    public string ContactPhone { get; set; } = "";
    public string Tagline { get; set; } = "";
    public string FooterText { get; set; } = "";
    public bool ShowCoverPage { get; set; } = true;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    public static async Task<BrandingConfig?> LoadAsync(string path)
    {
        if (!File.Exists(path)) return null;
        var json = await File.ReadAllTextAsync(path);
        return JsonSerializer.Deserialize<BrandingConfig>(json, Options);
    }

    [JsonIgnore]
    public bool HasLogo => LogoBase64.Length > 0;

    [JsonIgnore]
    public string EffectivePrimary => IsSafeCssColor(PrimaryColor) ? PrimaryColor : "#cba6f7";

    [JsonIgnore]
    public string EffectiveAccent => IsSafeCssColor(AccentColor) ? AccentColor : "#89b4fa";

    private static bool IsSafeCssColor(string value) =>
        !string.IsNullOrEmpty(value) && SafeCssColorPattern().IsMatch(value);

    [GeneratedRegex(@"^#[0-9a-fA-F]{3,8}$|^[a-zA-Z]{1,20}$|^rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)$")]
    private static partial Regex SafeCssColorPattern();
}

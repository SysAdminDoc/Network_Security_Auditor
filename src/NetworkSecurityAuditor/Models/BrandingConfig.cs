using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSecurityAuditor.Models;

public sealed class BrandingConfig
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
    public string EffectivePrimary => PrimaryColor.Length > 0 ? PrimaryColor : "#cba6f7";

    [JsonIgnore]
    public string EffectiveAccent => AccentColor.Length > 0 ? AccentColor : "#89b4fa";
}

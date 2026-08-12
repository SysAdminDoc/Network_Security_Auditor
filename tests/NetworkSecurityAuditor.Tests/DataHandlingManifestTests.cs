using System.Text.Json;
using NetworkSecurityAuditor.Export;

namespace NetworkSecurityAuditor.Tests;

public class DataHandlingManifestTests
{
    [Fact]
    public void Create_PrivacyMode_Declares_Redaction_And_Excludes_Secrets()
    {
        var manifest = DataHandlingManifestWriter.Create(
            privacyMode: true,
            [
                @"C:\Reports\SecurityAudit_[CLIENT-a1b2c3d4].json",
                @"C:\Reports\SecurityAudit_[CLIENT-a1b2c3d4].json"
            ]);

        Assert.True(manifest.PrivacyMode);
        Assert.Equal("sha256-pseudonym", manifest.IdentityStrategy);
        Assert.Equal("redacted", manifest.SourcePathPolicy);
        Assert.Equal("secret-excluded", manifest.FieldClassifications["credentials_and_tokens"]);
        Assert.Equal("operational-aggregate", manifest.FieldClassifications["fleet_kpis_and_denominators"]);
        Assert.Equal("restricted", manifest.FieldClassifications["dashboard_input_diagnostics"]);
        Assert.Contains("access_token", manifest.SecretFieldsExcluded);
        Assert.Single(manifest.Artifacts);
        Assert.Equal("pseudonymized", manifest.Redaction["hostnames"]);
    }

    [Fact]
    public void Create_NormalMode_States_That_Identities_Are_Present()
    {
        var manifest = DataHandlingManifestWriter.Create(false, ["report.html"]);

        Assert.False(manifest.PrivacyMode);
        Assert.Equal("present", manifest.IdentityStrategy);
        Assert.Equal("present", manifest.Redaction["domains"]);
    }

    [Fact]
    public void Serialization_Uses_Stable_DataHandling_Contract()
    {
        var manifest = DataHandlingManifestWriter.Create(true, ["report.json"]);
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true
        });

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal("1.0", root.GetProperty("schema_version").GetString());
        Assert.Equal("1.0", root.GetProperty("policy_version").GetString());
        Assert.True(root.GetProperty("privacy_mode").GetBoolean());
        Assert.True(root.TryGetProperty("field_classifications", out _));
        Assert.True(root.TryGetProperty("secret_fields_excluded", out _));
        Assert.DoesNotContain("C:\\", json, StringComparison.Ordinal);
    }
}

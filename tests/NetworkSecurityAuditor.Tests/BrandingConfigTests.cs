using System.IO;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class BrandingConfigTests
{
    [Fact]
    public async Task LoadAsync_ValidJson_LoadsAllFields()
    {
        var json = """
        {
            "company_name": "Acme Security",
            "logo_base64": "abc123",
            "primary_color": "#ff0000",
            "accent_color": "#00ff00",
            "contact_name": "Jane Doe",
            "contact_email": "jane@acme.com",
            "contact_phone": "555-1234",
            "tagline": "Securing the future",
            "footer_text": "Confidential",
            "show_cover_page": false
        }
        """;

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, json);
            var config = await BrandingConfig.LoadAsync(path);

            Assert.NotNull(config);
            Assert.Equal("Acme Security", config.CompanyName);
            Assert.Equal("abc123", config.LogoBase64);
            Assert.Equal("#ff0000", config.PrimaryColor);
            Assert.Equal("#00ff00", config.AccentColor);
            Assert.Equal("Jane Doe", config.ContactName);
            Assert.Equal("jane@acme.com", config.ContactEmail);
            Assert.Equal("555-1234", config.ContactPhone);
            Assert.Equal("Securing the future", config.Tagline);
            Assert.Equal("Confidential", config.FooterText);
            Assert.False(config.ShowCoverPage);
            Assert.True(config.HasLogo);
            Assert.Equal("#ff0000", config.EffectivePrimary);
            Assert.Equal("#00ff00", config.EffectiveAccent);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsNull()
    {
        var result = await BrandingConfig.LoadAsync(@"C:\nonexistent\path\brand.json");
        Assert.Null(result);
    }

    [Fact]
    public async Task LoadAsync_EmptyJson_ReturnsDefaults()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "{}");
            var config = await BrandingConfig.LoadAsync(path);

            Assert.NotNull(config);
            Assert.Equal("", config.CompanyName);
            Assert.False(config.HasLogo);
            Assert.Equal("#cba6f7", config.EffectivePrimary);
            Assert.Equal("#89b4fa", config.EffectiveAccent);
            Assert.True(config.ShowCoverPage);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_UnknownFields_Ignored()
    {
        var json = """
        {
            "company_name": "Test",
            "unknown_field": "should be ignored",
            "another_unknown": 42
        }
        """;

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, json);
            var config = await BrandingConfig.LoadAsync(path);

            Assert.NotNull(config);
            Assert.Equal("Test", config.CompanyName);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class PrivacyRedactorTests
{
    [Fact]
    public void Disabled_Redactor_Returns_Original()
    {
        var redactor = new PrivacyRedactor(false);
        Assert.Equal("WORKSTATION1", redactor.Redact("WORKSTATION1"));
    }

    [Fact]
    public void Redacts_Hostname()
    {
        var redactor = new PrivacyRedactor(true, computerName: "WORKSTATION1");
        var result = redactor.Redact("Found on WORKSTATION1 at 10:00");
        Assert.DoesNotContain("WORKSTATION1", result);
        Assert.Matches(@"\[HOST-[0-9a-f]{8}\]", result);
    }

    [Fact]
    public void Redacts_Domain()
    {
        var redactor = new PrivacyRedactor(true, computerName: "WS1", domainName: "CONTOSO.LOCAL");
        var result = redactor.Redact("Domain: CONTOSO.LOCAL");
        Assert.DoesNotContain("CONTOSO.LOCAL", result);
        Assert.Matches(@"\[DOMAIN-[0-9a-f]{8}\]", result);
    }

    [Fact]
    public void Redacts_IP_Addresses()
    {
        var redactor = new PrivacyRedactor(true);
        var result = redactor.Redact("Server at 192.168.1.100 responded");
        Assert.DoesNotContain("192.168.1.100", result);
        Assert.Matches(@"\[IP-[0-9a-f]{8}\]", result);
    }

    [Fact]
    public void Redacts_Bearer_Tokens()
    {
        var redactor = new PrivacyRedactor(true);
        var result = redactor.Redact("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.test");
        Assert.DoesNotContain("eyJhbGciOiJSUzI1NiJ9", result);
        Assert.Contains("[SECRET-REDACTED]", result);
    }

    [Fact]
    public void Redacts_Token_Parameters()
    {
        var redactor = new PrivacyRedactor(true);
        var result = redactor.Redact("url?access_token=abc123&refresh_token=xyz789");
        Assert.DoesNotContain("abc123", result);
        Assert.DoesNotContain("xyz789", result);
    }

    [Fact]
    public void Null_Input_Returns_Empty()
    {
        var redactor = new PrivacyRedactor(true, computerName: "TEST");
        Assert.Equal("", redactor.Redact(null));
    }

    [Fact]
    public void Case_Insensitive_Hostname()
    {
        var redactor = new PrivacyRedactor(true, computerName: "MyServer");
        var result = redactor.Redact("Connected to MYSERVER successfully");
        Assert.DoesNotContain("MYSERVER", result, StringComparison.OrdinalIgnoreCase);
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkSecurityAuditor.Services;

public sealed partial class PrivacyRedactor
{
    private readonly List<(Regex pattern, string replacement)> _replacements = [];

    public bool IsEnabled { get; }

    public PrivacyRedactor(bool enabled, string? computerName = null, string? domainName = null, string? userName = null, string? clientName = null, string? tenantName = null)
    {
        IsEnabled = enabled;
        if (!enabled) return;

        if (!string.IsNullOrEmpty(computerName))
            AddTarget(computerName, "HOST");
        if (!string.IsNullOrEmpty(domainName) && domainName != computerName)
            AddTarget(domainName, "DOMAIN");
        if (!string.IsNullOrEmpty(userName))
            AddTarget(userName, "USER");
        if (!string.IsNullOrEmpty(clientName) && clientName != computerName)
            AddTarget(clientName, "CLIENT");
        if (!string.IsNullOrEmpty(tenantName) && tenantName != domainName && tenantName != computerName)
            AddTarget(tenantName, "TENANT");
    }

    private void AddTarget(string value, string tag)
    {
        var hash = HashValue(value);
        _replacements.Add((
            new Regex(Regex.Escape(value), RegexOptions.IgnoreCase | RegexOptions.Compiled),
            $"[{tag}-{hash}]"
        ));
    }

    public string Redact(string? value)
    {
        if (!IsEnabled || string.IsNullOrEmpty(value)) return value ?? "";

        var text = value;

        foreach (var (pattern, replacement) in _replacements)
            text = pattern.Replace(text, replacement);

        text = IpPattern().Replace(text, m => $"[IP-{HashValue(m.Value)}]");
        text = TokenPattern().Replace(text, m => $"{m.Groups[1].Value}=[SECRET-REDACTED]");
        text = BearerPattern().Replace(text, "Bearer [SECRET-REDACTED]");

        return text;
    }

    private static string HashValue(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.ToLowerInvariant()));
        return Convert.ToHexString(bytes)[..8].ToLowerInvariant();
    }

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex IpPattern();

    [GeneratedRegex(@"(?i)\b(access_token|refresh_token|id_token|client_secret|token|secret)=([^&\s]+)")]
    private static partial Regex TokenPattern();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")]
    private static partial Regex BearerPattern();
}

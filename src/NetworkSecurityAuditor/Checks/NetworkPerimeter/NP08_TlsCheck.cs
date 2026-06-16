namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Text;
using Microsoft.Win32;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP08 - SSL/TLS Configuration: Check SCHANNEL registry settings. Flag if TLS 1.0/1.1
/// enabled, if TLS 1.2/1.3 not enabled.
/// </summary>
public sealed class NP08_TlsCheck : ISecurityCheck
{
    public string Id => "NP08";

    private static readonly string SchannelBase =
        @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasCritical = false;
            bool hasWarning = false;

            evidence.AppendLine("[SCHANNEL Protocol Configuration]");

            // Check each TLS/SSL version
            ct.ThrowIfCancellationRequested();

            // Deprecated protocols that should be disabled
            CheckProtocol("SSL 2.0", sb, evidence, ref hasCritical, isLegacy: true);
            CheckProtocol("SSL 3.0", sb, evidence, ref hasCritical, isLegacy: true);
            CheckProtocol("TLS 1.0", sb, evidence, ref hasCritical, isLegacy: true);
            CheckProtocol("TLS 1.1", sb, evidence, ref hasWarning, isLegacy: true);

            // Modern protocols that should be enabled
            CheckProtocol("TLS 1.2", sb, evidence, ref hasWarning, isLegacy: false);
            CheckProtocol("TLS 1.3", sb, evidence, ref hasWarning, isLegacy: false);

            // Check cipher suites
            ct.ThrowIfCancellationRequested();
            CheckCipherSuites(sb, evidence, ref hasWarning);

            // Check for weak ciphers
            ct.ThrowIfCancellationRequested();
            CheckWeakCiphers(sb, evidence, ref hasCritical);

            // Summary
            if (hasCritical)
                sb.Insert(0, "CRITICAL: Insecure SSL/TLS protocols are enabled.\n");
            else if (hasWarning)
                sb.Insert(0, "TLS configuration has warnings.\n");
            else
                sb.Insert(0, "TLS configuration appears secure.\n");

            var status = hasCritical ? CheckStatus.Fail
                : hasWarning ? CheckStatus.Partial
                : CheckStatus.Pass;

            return Task.FromResult(new CheckResult
            {
                Status = status,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void CheckProtocol(string protocol, StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, bool isLegacy)
    {
        string protocolPath = $@"{SchannelBase}\{protocol}";

        foreach (string role in new[] { "Server", "Client" })
        {
            string rolePath = $@"{protocolPath}\{role}";

            int enabled = RegistryHelper.GetValue<int>(rolePath, "Enabled", -1);
            int disabledByDefault = RegistryHelper.GetValue<int>(rolePath, "DisabledByDefault", -1);

            evidence.AppendLine($"  {protocol}/{role}: Enabled={FormatRegValue(enabled)}, " +
                $"DisabledByDefault={FormatRegValue(disabledByDefault)}");

            if (isLegacy)
            {
                // Legacy protocol: should be explicitly disabled
                if (enabled == 1 || (enabled == -1 && disabledByDefault != 1))
                {
                    // For SSL 2.0, it's disabled by default on modern Windows even without registry keys
                    // But TLS 1.0 is enabled by default on most Windows versions
                    if (protocol is "TLS 1.0" or "TLS 1.1")
                    {
                        if (enabled == 1)
                        {
                            hasIssue = true;
                            sb.AppendLine($"WARNING: {protocol} ({role}) is explicitly enabled. " +
                                "Disable this deprecated protocol.");
                        }
                        else if (enabled == -1 && disabledByDefault != 1)
                        {
                            // Not explicitly configured - defaults to enabled on many OS versions
                            sb.AppendLine($"INFO: {protocol} ({role}) has no explicit registry setting. " +
                                "May be enabled by OS default. Explicitly disable for hardened configuration.");
                        }
                    }
                    else if (protocol.StartsWith("SSL") && enabled == 1)
                    {
                        hasIssue = true;
                        sb.AppendLine($"CRITICAL: {protocol} ({role}) is explicitly enabled. " +
                            "This is severely insecure and must be disabled.");
                    }
                }
            }
            else
            {
                // Modern protocol: should be enabled
                if (enabled == 0)
                {
                    hasIssue = true;
                    sb.AppendLine($"WARNING: {protocol} ({role}) is explicitly disabled. " +
                        "This modern protocol should be enabled.");
                }
            }
        }
    }

    private static void CheckCipherSuites(StringBuilder sb, StringBuilder evidence, ref bool hasWarning)
    {
        evidence.AppendLine("\n[Cipher Suite Order]");

        string cipherPath = @"HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002";
        string? cipherOrder = RegistryHelper.GetValue<string>(cipherPath, "Functions", null);

        if (!string.IsNullOrEmpty(cipherOrder))
        {
            var suites = cipherOrder.Split(',');
            evidence.AppendLine($"  Configured cipher suites: {suites.Length}");

            foreach (string suite in suites.Take(10))
                evidence.AppendLine($"    {suite.Trim()}");

            if (suites.Length > 10)
                evidence.AppendLine($"    ... and {suites.Length - 10} more");
        }
        else
        {
            evidence.AppendLine("  No custom cipher suite order configured (using OS defaults).");
        }
    }

    private static void CheckWeakCiphers(StringBuilder sb, StringBuilder evidence, ref bool hasCritical)
    {
        evidence.AppendLine("\n[Weak Cipher Check]");

        string ciphersPath = @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";

        string[] weakCiphers = ["RC4 128/128", "RC4 56/128", "RC4 40/128", "RC2 128/128",
            "RC2 56/128", "RC2 40/128", "DES 56/56", "NULL"];

        foreach (string cipher in weakCiphers)
        {
            string cipherPath = $@"{ciphersPath}\{cipher}";
            int enabled = RegistryHelper.GetValue<int>(cipherPath, "Enabled", -1);

            if (enabled == 1)
            {
                hasCritical = true;
                evidence.AppendLine($"  ENABLED: {cipher}");
                sb.AppendLine($"CRITICAL: Weak cipher \"{cipher}\" is explicitly enabled. Disable immediately.");
            }
            else if (enabled == 0)
            {
                evidence.AppendLine($"  Disabled: {cipher} (good)");
            }
        }
    }

    private static string FormatRegValue(int value) => value switch
    {
        -1 => "Not set",
        0 => "0 (Disabled)",
        1 => "1 (Enabled)",
        _ => value.ToString()
    };
}

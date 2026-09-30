namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA03 - Local MFA/Strong Auth Signals: RDP NLA, Windows Hello policy,
/// installed MFA agents and smart card enforcement, with the ADFS service noted but not counted.
/// These are local indicators only, not tenant MFA proof.
/// </summary>
public sealed partial class IA03_MfaSignalsCheck : ISecurityCheck
{
    public string Id => "IA03";

    private readonly IRegistryReader _registry;

    public IA03_MfaSignalsCheck() : this(SystemRegistryReader.Instance) { }

    internal IA03_MfaSignalsCheck(IRegistryReader registry) => _registry = registry;

    // Product names matched as whole words (or word sequences) in the program's DisplayName. A substring match
    // counted "Universal CRT" as RSA, "Snipping Tool" as Ping and "Duolingo" as Duo, and two false hits made IA03
    // Pass. The PS1 IA03 block carries the same list, and a test keeps them identical.
    internal static readonly (string Phrase, string Label)[] MfaAgents =
    [
        ("duo authentication", "Duo Security"),
        ("duo security", "Duo Security"),
        ("duo device health", "Duo Security"),
        ("rsa securid", "RSA SecurID"),
        ("rsa authentication agent", "RSA SecurID"),
        ("okta verify", "Okta Verify"),
        ("authlite", "AuthLite"),
        ("yubikey", "YubiKey"),
        ("yubico login", "YubiKey"),
        ("safenet authentication", "Thales/SafeNet"),
        ("cyberark identity", "CyberArk Identity"),
        ("pingid", "PingID"),
        ("azure mfa", "Azure AD MFA"),
        ("azure ad mfa", "Azure AD MFA"),
        ("azure multi factor authentication", "Azure AD MFA"),
        ("microsoft authenticator", "Microsoft Authenticator"),
        ("fortitoken", "FortiToken"),
        ("symantec vip", "Symantec VIP"),
        ("vip access", "Symantec VIP"),
        ("authpoint", "WatchGuard AuthPoint"),
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int signalCount = 0;

            // 1. RDP Network Level Authentication
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[RDP NLA]");
            int nla = _registry.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication", -1);
            evidence.AppendLine($"  UserAuthentication = {nla}");

            if (nla == 1)
            {
                sb.AppendLine("PASS: RDP Network Level Authentication (NLA) is enabled.");
                signalCount++;
            }
            else if (nla == 0)
            {
                sb.AppendLine("FAIL: RDP NLA is DISABLED. Pre-authentication bypass risk.");
            }
            else
            {
                sb.AppendLine("INFO: RDP NLA setting not found (RDP may be disabled).");
            }

            // 2. Windows Hello for Business
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Windows Hello for Business]");

            int helloEnabled = _registry.GetValue<int>(
                @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "Enabled", -1);
            int helloRequireSec = _registry.GetValue<int>(
                @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "RequireSecurityDevice", 0);

            evidence.AppendLine($"  PassportForWork\\Enabled = {helloEnabled}");
            evidence.AppendLine($"  RequireSecurityDevice = {helloRequireSec}");

            if (helloEnabled == 1)
            {
                sb.AppendLine("PASS: Windows Hello for Business policy is enabled.");
                signalCount++;
                if (helloRequireSec == 1)
                    sb.AppendLine("  INFO: Hardware security device (TPM) required.");
            }
            else if (helloEnabled == 0)
            {
                sb.AppendLine("INFO: Windows Hello for Business is explicitly disabled by policy.");
            }
            else
            {
                sb.AppendLine("INFO: Windows Hello for Business policy not configured.");
            }

            // 3. Installed MFA agents (scan uninstall registry)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Installed MFA Agents]");
            var detectedAgents = new List<string>();

            string[] uninstallPaths =
            [
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ];

            foreach (var basePath in uninstallPaths)
            {
                var subkeys = _registry.GetSubKeyNames(basePath);
                foreach (var subkey in subkeys)
                {
                    ct.ThrowIfCancellationRequested();
                    string displayName = _registry.GetValue<string>(
                        $@"{basePath}\{subkey}", "DisplayName", "") ?? "";

                    if (MatchMfaAgent(displayName) is { } label && !detectedAgents.Contains(label))
                    {
                        detectedAgents.Add(label);
                        evidence.AppendLine($"  FOUND: {label} ({displayName})");
                    }
                }
            }

            if (detectedAgents.Count > 0)
            {
                sb.AppendLine($"MFA agents detected: {string.Join(", ", detectedAgents)}");
                signalCount += detectedAgents.Count;
            }
            else
            {
                sb.AppendLine("No MFA agent software detected in installed programs.");
            }

            // 4. Smart card enforcement
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Smart Card Policy]");

            int scForceOption = _registry.GetValue<int>(
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "scforceoption", 0);
            evidence.AppendLine($"  scforceoption = {scForceOption}");

            if (scForceOption == 1)
            {
                sb.AppendLine("PASS: Smart card logon is enforced (interactive logon requires smart card).");
                signalCount++;
            }
            else
            {
                sb.AppendLine("INFO: Smart card logon is not enforced.");
            }

            // 5. ADFS service indicator. Noted only: federation can run with password-only sign-in, so ADFS isn't MFA.
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[ADFS Service]");

            bool adfsKeyExists = _registry.KeyExists(@"HKLM\SOFTWARE\Microsoft\ADFS");
            evidence.AppendLine($"  ADFS registry key exists = {adfsKeyExists}");

            if (adfsKeyExists)
                sb.AppendLine("INFO: ADFS registry key detected. Federation service may be installed on this server. ADFS alone isn't MFA, so it isn't counted as a signal.");

            // Summary
            sb.Insert(0, $"MFA/Strong Auth signals found: {signalCount}\n" +
                         "NOTE: These are local indicators only; they do not prove tenant-wide MFA enforcement.\n\n");

            var status = signalCount >= 2 ? CheckStatus.Pass
                       : signalCount >= 1 ? CheckStatus.Partial
                       : CheckStatus.Fail;

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

    /// <summary>The label of the MFA agent named in <paramref name="displayName"/> as whole words, or null.</summary>
    internal static string? MatchMfaAgent(string? displayName)
    {
        if (string.IsNullOrEmpty(displayName)) return null;
        var words = WordSeparator().Split(displayName.ToLowerInvariant()).Where(w => w.Length > 0).ToArray();
        foreach (var (phrase, label) in MfaAgents)
        {
            var parts = phrase.Split(' ');
            for (int i = 0; i + parts.Length <= words.Length; i++)
            {
                if (parts.Select((part, k) => words[i + k] == part).All(hit => hit))
                    return label;
            }
        }
        return null;
    }

    [GeneratedRegex(@"[^\p{L}\p{Nd}]+")]
    private static partial Regex WordSeparator();
}

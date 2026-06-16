namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA03 - Local MFA/Strong Auth Signals: RDP NLA, Windows Hello policy,
/// installed MFA agents, smart card enforcement, ADFS service.
/// These are local indicators only, not tenant MFA proof.
/// </summary>
public sealed class IA03_MfaSignalsCheck : ISecurityCheck
{
    public string Id => "IA03";

    private static readonly Dictionary<string, string> MfaAgentPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        { "Duo", "Duo Security" },
        { "RSA", "RSA SecurID" },
        { "Okta", "Okta Verify" },
        { "AuthLite", "AuthLite" },
        { "YubiKey", "YubiKey" },
        { "Thales", "Thales/SafeNet" },
        { "CyberArk", "CyberArk Identity" },
        { "Ping", "PingID" },
        { "Azure AD MFA", "Azure AD MFA" },
        { "Microsoft Authenticator", "Microsoft Authenticator" },
        { "FortiToken", "FortiToken" },
        { "Symantec VIP", "Symantec VIP" },
    };

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
            int nla = RegistryHelper.GetValue<int>(
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

            int helloEnabled = RegistryHelper.GetValue<int>(
                @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "Enabled", -1);
            int helloRequireSec = RegistryHelper.GetValue<int>(
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
                var subkeys = RegistryHelper.GetSubKeyNames(basePath);
                foreach (var subkey in subkeys)
                {
                    ct.ThrowIfCancellationRequested();
                    string displayName = RegistryHelper.GetValue<string>(
                        $@"{basePath}\{subkey}", "DisplayName", "") ?? "";

                    foreach (var (pattern, label) in MfaAgentPatterns)
                    {
                        if (displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!detectedAgents.Contains(label))
                            {
                                detectedAgents.Add(label);
                                evidence.AppendLine($"  FOUND: {label} ({displayName})");
                            }
                        }
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

            int scForceOption = RegistryHelper.GetValue<int>(
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

            // 5. ADFS service indicator
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[ADFS Service]");

            bool adfsKeyExists = RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\ADFS");
            evidence.AppendLine($"  ADFS registry key exists = {adfsKeyExists}");

            if (adfsKeyExists)
            {
                sb.AppendLine("INFO: ADFS registry key detected. Federation service may be installed on this server.");
                signalCount++;
            }

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
}

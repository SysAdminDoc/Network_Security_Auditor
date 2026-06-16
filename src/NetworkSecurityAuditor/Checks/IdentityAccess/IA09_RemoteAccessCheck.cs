namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Net.NetworkInformation;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA09 - Remote Access Audit: RDP status/NLA/port, VPN adapters,
/// remote access software (TeamViewer, AnyDesk, etc.), RMM indicators.
/// </summary>
public sealed class IA09_RemoteAccessCheck : ISecurityCheck
{
    public string Id => "IA09";

    private static readonly Dictionary<string, string> RemoteAccessSoftware = new(StringComparer.OrdinalIgnoreCase)
    {
        { "TeamViewer", "TeamViewer" },
        { "AnyDesk", "AnyDesk" },
        { "ScreenConnect", "ConnectWise ScreenConnect" },
        { "ConnectWise Control", "ConnectWise Control" },
        { "LogMeIn", "LogMeIn" },
        { "GoToAssist", "GoToAssist" },
        { "Splashtop", "Splashtop" },
        { "BeyondTrust", "BeyondTrust" },
        { "Bomgar", "BeyondTrust (Bomgar)" },
        { "RustDesk", "RustDesk" },
        { "VNC", "VNC" },
        { "TightVNC", "TightVNC" },
        { "RealVNC", "RealVNC" },
        { "UltraVNC", "UltraVNC" },
        { "Radmin", "Radmin" },
        { "RemotePC", "RemotePC" },
        { "Chrome Remote Desktop", "Chrome Remote Desktop" },
        { "Parsec", "Parsec" },
    };

    private static readonly Dictionary<string, string> RmmPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        { "Datto", "Datto RMM" },
        { "NinjaRMM", "NinjaRMM" },
        { "NinjaOne", "NinjaOne" },
        { "Atera", "Atera" },
        { "ConnectWise Automate", "ConnectWise Automate" },
        { "SyncroMSP", "SyncroMSP" },
        { "N-able", "N-able" },
        { "N-central", "N-central" },
        { "Kaseya", "Kaseya VSA" },
        { "Huntress", "Huntress" },
        { "Continuum", "Continuum" },
        { "Pulseway", "Pulseway" },
        { "Level.io", "Level" },
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. RDP configuration
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[RDP Configuration]");

            int rdpDisabled = RegistryHelper.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections", 1);
            bool rdpEnabled = rdpDisabled == 0;

            int nla = RegistryHelper.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication", -1);

            int rdpPort = RegistryHelper.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "PortNumber", 3389);

            evidence.AppendLine($"  fDenyTSConnections = {rdpDisabled} (RDP {(rdpEnabled ? "ENABLED" : "disabled")})");
            evidence.AppendLine($"  UserAuthentication (NLA) = {nla}");
            evidence.AppendLine($"  RDP Port = {rdpPort}");

            if (rdpEnabled)
            {
                sb.AppendLine($"RDP is ENABLED on port {rdpPort}.");
                if (nla != 1)
                {
                    hasIssue = true;
                    sb.AppendLine("  FAIL: NLA (Network Level Authentication) is NOT enabled for RDP.");
                }
                else
                {
                    sb.AppendLine("  PASS: NLA is enabled.");
                }

                if (rdpPort != 3389)
                    sb.AppendLine($"  INFO: Non-standard RDP port ({rdpPort}). Security through obscurity alone is insufficient.");
            }
            else
            {
                sb.AppendLine("RDP is disabled.");
            }

            // 2. VPN adapters
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[VPN Adapters]");
            var vpnAdapters = new List<string>();

            try
            {
                var nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var nic in nics)
                {
                    string desc = nic.Description;
                    string name = nic.Name;

                    // Common VPN adapter patterns
                    bool isVpn = desc.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("TAP-", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("Cisco AnyConnect", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("Fortinet", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("FortiClient", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("GlobalProtect", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("SonicWall", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("Juniper", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("Pulse Secure", StringComparison.OrdinalIgnoreCase) ||
                                 desc.Contains("ZScaler", StringComparison.OrdinalIgnoreCase) ||
                                 nic.NetworkInterfaceType == NetworkInterfaceType.Ppp;

                    if (isVpn)
                    {
                        vpnAdapters.Add($"{name} ({desc})");
                        evidence.AppendLine($"  {name} | {desc} | Status={nic.OperationalStatus}");
                    }
                }
            }
            catch (Exception ex)
            {
                evidence.AppendLine($"  Error enumerating adapters: {ex.Message}");
            }

            if (vpnAdapters.Count > 0)
                sb.AppendLine($"VPN adapters detected: {string.Join(", ", vpnAdapters)}");
            else
                sb.AppendLine("No VPN adapters detected.");

            // 3. Remote access software
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Remote Access Software]");
            var detectedRemote = ScanUninstallRegistry(RemoteAccessSoftware, evidence, ct);

            if (detectedRemote.Count > 0)
            {
                sb.AppendLine($"Remote access software detected: {string.Join(", ", detectedRemote)}");
                sb.AppendLine("  Review: unauthorized remote access tools are a common breach vector.");
            }
            else
            {
                sb.AppendLine("No third-party remote access software detected.");
            }

            // 4. RMM indicators
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[RMM Indicators]");
            var detectedRmm = ScanUninstallRegistry(RmmPatterns, evidence, ct);

            if (detectedRmm.Count > 0)
                sb.AppendLine($"RMM agents detected: {string.Join(", ", detectedRmm)}");
            else
                sb.AppendLine("No RMM agents detected in installed software.");

            // Flag if multiple remote access tools found
            int totalRemoteTools = detectedRemote.Count + detectedRmm.Count;
            if (totalRemoteTools > 2)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {totalRemoteTools} remote management tools detected. Consolidate to reduce attack surface.");
            }

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static List<string> ScanUninstallRegistry(
        Dictionary<string, string> patterns, StringBuilder evidence, CancellationToken ct)
    {
        var detected = new List<string>();

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

                foreach (var (pattern, label) in patterns)
                {
                    if (displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                        !detected.Contains(label))
                    {
                        detected.Add(label);
                        evidence.AppendLine($"  FOUND: {label} ({displayName})");
                    }
                }
            }
        }

        return detected;
    }
}

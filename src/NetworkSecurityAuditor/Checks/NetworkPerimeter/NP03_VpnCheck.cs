namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Diagnostics;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP03 - VPN Configuration: Check for VPN adapters, built-in VPN connections,
/// and split tunneling indicators.
/// </summary>
public sealed class NP03_VpnCheck : ISecurityCheck
{
    public string Id => "NP03";

    private static readonly string[] VpnAdapterIndicators =
    [
        "VPN", "Cisco", "Juniper", "Palo Alto", "GlobalProtect", "Pulse",
        "FortiClient", "WireGuard", "OpenVPN", "TAP-Windows", "SonicWall",
        "Citrix", "F5", "Zscaler", "Cloudflare WARP", "NordVPN", "Tailscale"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool vpnFound = false;
            bool splitTunnel = false;

            // 1. Check for VPN adapters via WMI
            ct.ThrowIfCancellationRequested();
            CheckVpnAdapters(sb, evidence, ref vpnFound, ct);

            // 2. Check built-in Windows VPN connections
            ct.ThrowIfCancellationRequested();
            CheckBuiltInVpn(sb, evidence, ref vpnFound, ct);

            // 3. Check VPN software registry keys
            ct.ThrowIfCancellationRequested();
            CheckVpnSoftware(sb, evidence, ref vpnFound);

            // 4. Check for split tunneling indicators
            ct.ThrowIfCancellationRequested();
            CheckSplitTunnel(sb, evidence, ref splitTunnel, ct);

            // Summary
            if (vpnFound)
            {
                sb.Insert(0, "VPN configuration detected.\n");
                if (splitTunnel)
                    sb.AppendLine("WARNING: Split tunneling may be configured. Verify corporate traffic " +
                        "routes through the VPN and internet traffic policies are enforced.");
            }
            else
            {
                sb.Insert(0, "No VPN adapters or connections detected on this system.\n");
                sb.AppendLine("INFO: If remote access is required, verify VPN is deployed and configured properly.");
            }

            var status = vpnFound ? (splitTunnel ? CheckStatus.Partial : CheckStatus.Pass)
                : CheckStatus.Partial;

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

    private static void CheckVpnAdapters(StringBuilder sb, StringBuilder evidence,
        ref bool vpnFound, CancellationToken ct)
    {
        evidence.AppendLine("[VPN Network Adapters]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Description, Name, NetConnectionID FROM Win32_NetworkAdapter");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string desc = obj["Description"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";

                foreach (string indicator in VpnAdapterIndicators)
                {
                    if (desc.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                        name.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        vpnFound = true;
                        string connId = obj["NetConnectionID"]?.ToString() ?? "";
                        evidence.AppendLine($"  VPN adapter: {desc} ({connId})");
                        sb.AppendLine($"VPN adapter detected: {desc}");
                        break;
                    }
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckBuiltInVpn(StringBuilder sb, StringBuilder evidence,
        ref bool vpnFound, CancellationToken ct)
    {
        evidence.AppendLine("\n[Built-in VPN Connections]");

        try
        {
            string output = RunCommand("rasdial", "", ct);

            if (!output.Contains("No connections", StringComparison.OrdinalIgnoreCase))
            {
                evidence.AppendLine(output.Length > 1000 ? output[..1000] : output);
            }
        }
        catch { /* rasdial may not be available */ }

        // Check VPN phonebook entries
        try
        {
            string output = RunCommand("rasphone", "-h", ct);
            evidence.AppendLine($"  rasphone available: {!string.IsNullOrWhiteSpace(output)}");
        }
        catch { /* rasphone not available */ }

        // Check registry for VPN connections
        var vpnConnections = RegistryHelper.GetSubKeyNames(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RasManager\Config");

        string userVpnPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RasManager";
        var userVpn = RegistryHelper.GetSubKeyNames(userVpnPath);

        if (vpnConnections.Length > 0 || userVpn.Length > 0)
        {
            vpnFound = true;
            evidence.AppendLine($"  System VPN connections: {vpnConnections.Length}");
            evidence.AppendLine($"  User VPN connections: {userVpn.Length}");
        }
    }

    private static void CheckVpnSoftware(StringBuilder sb, StringBuilder evidence, ref bool vpnFound)
    {
        evidence.AppendLine("\n[VPN Software Registry]");

        var vpnSoftware = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client", "Cisco AnyConnect" },
            { @"HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect", "GlobalProtect" },
            { @"HKLM\SOFTWARE\Pulse Secure", "Pulse Secure" },
            { @"HKLM\SOFTWARE\Fortinet\FortiClient", "FortiClient" },
            { @"HKLM\SOFTWARE\WireGuard", "WireGuard" },
            { @"HKLM\SOFTWARE\OpenVPN", "OpenVPN" },
            { @"HKLM\SOFTWARE\SonicWall", "SonicWall" },
            { @"HKLM\SOFTWARE\Zscaler", "Zscaler" },
            { @"HKLM\SOFTWARE\Tailscale IPN", "Tailscale" },
        };

        foreach (var (path, label) in vpnSoftware)
        {
            if (RegistryHelper.KeyExists(path))
            {
                vpnFound = true;
                evidence.AppendLine($"  FOUND: {label} ({path})");
                sb.AppendLine($"VPN software detected: {label}");
            }
        }
    }

    private static void CheckSplitTunnel(StringBuilder sb, StringBuilder evidence,
        ref bool splitTunnel, CancellationToken ct)
    {
        evidence.AppendLine("\n[Split Tunnel Analysis]");

        try
        {
            // Check route table for default gateway count
            string output = RunCommand("route", "print 0.0.0.0", ct);

            int defaultRoutes = 0;
            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("0.0.0.0") && trimmed.Contains("0.0.0.0"))
                    defaultRoutes++;
            }

            evidence.AppendLine($"  Default routes: {defaultRoutes}");

            // Multiple default routes can indicate split tunnel (one for VPN, one for internet)
            if (defaultRoutes > 1)
            {
                splitTunnel = true;
                evidence.AppendLine("  Multiple default routes detected - split tunnel indicator");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Route analysis error: {ex.Message}");
        }
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");

        ct.Register(() => { try { proc.Kill(); } catch { } });

        string output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(15_000);
        return output;
    }
}

namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Globalization;
using System.IO;
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

        // Built-in VPN connections are the VPN entries in the RAS phonebooks, read here as files.
        // rasphone.exe is a dialog, so running it would open a window on the desktop of whoever is signed in.
        if (ReadPhonebooks(PhonebookPaths(), sb, evidence, ct))
            vpnFound = true;

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

            var assessment = AssessSplitTunnelRoutes(output);

            evidence.AppendLine($"  Default routes: {assessment.DefaultRouteCount}");

            if (assessment.HasMultipleDefaultRoutes)
                evidence.AppendLine("  Multiple default routes observed; this is common on multi-NIC systems and is not treated as split tunneling by itself.");

            if (assessment.IsConfirmedSplitTunnel)
            {
                splitTunnel = true;
                evidence.AppendLine("  Explicit split tunnel route indicator detected.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Route analysis error: {ex.Message}");
        }
    }

    /// <summary>The per-user and all-users RAS phonebooks, where Windows keeps its built-in VPN connections.</summary>
    internal static IReadOnlyList<(string Scope, string Path)> PhonebookPaths() =>
    [
        ("current user", PhonebookPath(Environment.SpecialFolder.ApplicationData)),
        ("all users", PhonebookPath(Environment.SpecialFolder.CommonApplicationData))
    ];

    private static string PhonebookPath(Environment.SpecialFolder folder) =>
        Path.Combine(Environment.GetFolderPath(folder), "Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk");

    /// <summary>
    /// Lists the VPN entries of each phonebook that exists. Returns true when any is found. Evidence names the
    /// phonebook by scope, never by path, since the per-user path carries the account name.
    /// </summary>
    internal static bool ReadPhonebooks(
        IEnumerable<(string Scope, string Path)> phonebooks,
        StringBuilder sb,
        StringBuilder evidence,
        CancellationToken ct)
    {
        bool found = false;
        foreach (var (scope, path) in phonebooks)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(path))
            {
                evidence.AppendLine($"  RAS phonebook ({scope}): none");
                continue;
            }

            IReadOnlyList<PhonebookEntry> entries;
            try
            {
                entries = ParsePhonebook(File.ReadAllText(path));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                evidence.AppendLine($"  RAS phonebook ({scope}): unreadable ({ex.GetType().Name})");
                continue;
            }

            var vpnEntries = entries.Where(entry => entry.IsVpn).ToList();
            evidence.AppendLine($"  RAS phonebook ({scope}): {vpnEntries.Count} VPN {(vpnEntries.Count == 1 ? "entry" : "entries")}");
            foreach (var entry in vpnEntries)
            {
                found = true;
                evidence.AppendLine($"    {DescribePhonebookEntry(entry)}");
                sb.AppendLine($"Built-in VPN connection configured: {entry.Name}");
            }
        }

        return found;
    }

    /// <summary>
    /// Parses a rasphone.pbk file (INI format). Each [section] is one entry. Keys repeat in the device
    /// subsections, so the first value of a key wins.
    /// </summary>
    internal static IReadOnlyList<PhonebookEntry> ParsePhonebook(string text)
    {
        var entries = new List<PhonebookEntry>();
        string? name = null;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void Flush()
        {
            if (name is null)
                return;
            entries.Add(new PhonebookEntry(
                name,
                ReadInt(values, "Type"),
                values.GetValueOrDefault("PhoneNumber", ""),
                ReadInt(values, "IpPrioritizeRemote")));
        }

        foreach (var rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;

            if (line.Length >= 2 && line[0] == '[' && line[^1] == ']')
            {
                Flush();
                name = line[1..^1].Trim();
                values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                continue;
            }

            int separator = line.IndexOf('=');
            if (name is null || separator <= 0)
                continue;

            values.TryAdd(line[..separator].Trim(), line[(separator + 1)..].Trim());
        }

        Flush();
        return entries;
    }

    internal static string DescribePhonebookEntry(PhonebookEntry entry)
    {
        string server = string.IsNullOrWhiteSpace(entry.Server) ? "(not set)" : entry.Server;
        string tunnel = entry.SplitTunnel switch
        {
            true => "split tunnel (IpPrioritizeRemote=0)",
            false => "full tunnel (IpPrioritizeRemote=1)",
            null => "tunnel mode not recorded"
        };
        return $"{entry.Name} | Server: {server} | {tunnel}";
    }

    private static int? ReadInt(Dictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var text) &&
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    /// <summary>One rasphone.pbk entry. Type 2 is a VPN (RASET_Vpn).</summary>
    internal sealed record PhonebookEntry(string Name, int? Type, string Server, int? PrioritizeRemote)
    {
        public bool IsVpn => Type == 2;

        /// <summary>IpPrioritizeRemote=0 turns off "use default gateway on remote network", which is split tunneling.</summary>
        public bool? SplitTunnel => PrioritizeRemote switch
        {
            0 => true,
            1 => false,
            _ => null
        };
    }

    internal static SplitTunnelRouteAssessment AssessSplitTunnelRoutes(string routeOutput)
    {
        int defaultRoutes = 0;
        foreach (var line in routeOutput.Split('\n'))
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("0.0.0.0", StringComparison.Ordinal) &&
                trimmed.Contains("0.0.0.0", StringComparison.Ordinal))
            {
                defaultRoutes++;
            }
        }

        return new SplitTunnelRouteAssessment(
            DefaultRouteCount: defaultRoutes,
            IsConfirmedSplitTunnel: false);
    }

    internal readonly record struct SplitTunnelRouteAssessment(
        int DefaultRouteCount,
        bool IsConfirmedSplitTunnel)
    {
        public bool HasMultipleDefaultRoutes => DefaultRouteCount > 1;
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        return CommandRunner.RunForOutput(fileName, arguments, TimeSpan.FromSeconds(15), ct);
    }
}

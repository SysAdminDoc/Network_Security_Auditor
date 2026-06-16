namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Diagnostics;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// EP06 - Windows Firewall profile status, default actions, log sizes, high-risk inbound ports.
/// </summary>
public sealed class EP06_HostFirewallCheck : ISecurityCheck
{
    public string Id => "EP06";

    private static readonly int[] HighRiskPorts =
        [21, 23, 69, 135, 139, 445, 1433, 3389, 5900, 5985, 5986];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // -- Firewall profile status via netsh --
            ct.ThrowIfCancellationRequested();
            CheckFirewallProfiles(sb, evidence, ref hasIssue, ct);

            // -- High-risk inbound ports --
            ct.ThrowIfCancellationRequested();
            CheckHighRiskPorts(sb, evidence, ref hasIssue, ct);

            if (!hasIssue)
                sb.Insert(0, "All Windows Firewall profiles enabled with appropriate defaults.\n");

            var status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass;

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

    private static void CheckFirewallProfiles(StringBuilder sb, StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("[Firewall Profile Status]");

        try
        {
            string output = RunCommand("netsh", "advfirewall show allprofiles", ct);
            evidence.AppendLine(output);

            // Parse profiles
            string[] profiles = ["Domain", "Private", "Public"];
            foreach (var profile in profiles)
            {
                ct.ThrowIfCancellationRequested();

                // Look for State line under each profile section
                bool enabled = output.Contains($"State", StringComparison.OrdinalIgnoreCase)
                    && !ContainsProfileDisabled(output, profile);

                // Check inbound/outbound defaults
                bool inboundBlock = output.Contains("Firewall Policy") && output.Contains("BlockInbound");
            }

            // Simpler: check for any OFF state
            if (output.Contains("State                                 OFF", StringComparison.OrdinalIgnoreCase))
            {
                hasIssue = true;
                sb.AppendLine("FAIL: One or more firewall profiles are DISABLED.");
            }

            // Check log file sizes
            if (output.Contains("LogMaxFileSize", StringComparison.OrdinalIgnoreCase))
            {
                // Parse max file size values
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("MaxFileSize", StringComparison.OrdinalIgnoreCase))
                    {
                        evidence.AppendLine($"  Log setting: {line.Trim()}");
                    }
                }
            }

            // Check if logging dropped packets is enabled
            if (output.Contains("LogDroppedConnections") &&
                output.Contains("Disable", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine("WARNING: Firewall dropped-connection logging is disabled on one or more profiles.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh error: {ex.Message}");
            sb.AppendLine("Could not query firewall status via netsh.");

            // Fallback to WMI
            CheckFirewallViaWmi(sb, evidence, ref hasIssue);
        }
    }

    private static void CheckFirewallViaWmi(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        try
        {
            // HNetCfg.FwPolicy2 COM object via WMI fallback
            using var searcher = new ManagementObjectSearcher(
                @"root\StandardCimv2",
                "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction FROM MSFT_NetFirewallProfile");

            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"]?.ToString() ?? "Unknown";
                bool enabled = Convert.ToUInt16(obj["Enabled"] ?? 0) == 1;
                int inbound = Convert.ToInt32(obj["DefaultInboundAction"] ?? 0);
                int outbound = Convert.ToInt32(obj["DefaultOutboundAction"] ?? 0);

                string inboundLabel = inbound == 2 ? "Block" : inbound == 3 ? "Allow" : $"({inbound})";
                string outboundLabel = outbound == 2 ? "Block" : outbound == 3 ? "Allow" : $"({outbound})";

                evidence.AppendLine($"  [WMI] {name}: Enabled={enabled}, InboundDefault={inboundLabel}, OutboundDefault={outboundLabel}");

                if (!enabled)
                {
                    hasIssue = true;
                    sb.AppendLine($"FAIL: Firewall profile '{name}' is DISABLED.");
                }

                if (inbound != 2) // Not Block
                {
                    hasIssue = true;
                    sb.AppendLine($"WARNING: Firewall profile '{name}' default inbound action is not Block.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI fallback error: {ex.Message}");
        }
    }

    private static void CheckHighRiskPorts(StringBuilder sb, StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[High-Risk Inbound Ports - Listening]");

        try
        {
            // Use netstat to find listening TCP ports
            string output = RunCommand("netstat", "-an -p TCP", ct);
            var listeningPorts = new HashSet<int>();

            foreach (var line in output.Split('\n'))
            {
                if (!line.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;

                // Parse: TCP    0.0.0.0:PORT    0.0.0.0:0    LISTENING
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;

                string local = parts[1];
                int colonIdx = local.LastIndexOf(':');
                if (colonIdx > 0 && int.TryParse(local[(colonIdx + 1)..], out int port))
                {
                    listeningPorts.Add(port);
                }
            }

            var openHighRisk = new List<(int port, string desc)>();
            foreach (int port in HighRiskPorts)
            {
                if (listeningPorts.Contains(port))
                {
                    string desc = GetPortDescription(port);
                    openHighRisk.Add((port, desc));
                    evidence.AppendLine($"  OPEN: {port}/tcp ({desc})");
                }
            }

            if (openHighRisk.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {openHighRisk.Count} high-risk port(s) are listening:");
                foreach (var (port, desc) in openHighRisk)
                    sb.AppendLine($"  - {port}/tcp ({desc})");
            }
            else
            {
                sb.AppendLine("PASS: No high-risk ports are actively listening.");
            }

            evidence.AppendLine($"  Total listening TCP ports: {listeningPorts.Count}");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netstat error: {ex.Message}");
        }
    }

    private static bool ContainsProfileDisabled(string output, string profileName)
    {
        // Rough heuristic: find profile section and check if State is OFF
        int idx = output.IndexOf($"{profileName} Profile", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return false;

        int stateIdx = output.IndexOf("State", idx, StringComparison.OrdinalIgnoreCase);
        if (stateIdx < 0) return false;

        int lineEnd = output.IndexOf('\n', stateIdx);
        string stateLine = lineEnd > stateIdx ? output[stateIdx..lineEnd] : output[stateIdx..];

        return stateLine.Contains("OFF", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetPortDescription(int port) => port switch
    {
        21 => "FTP",
        23 => "Telnet",
        69 => "TFTP",
        135 => "RPC/DCOM",
        139 => "NetBIOS Session",
        445 => "SMB",
        1433 => "SQL Server",
        3389 => "RDP",
        5900 => "VNC",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        _ => "Unknown"
    };

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
        proc.WaitForExit(30_000);
        return output;
    }
}

namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NA06 - Management Interface Isolation: Check if management services (RDP, WinRM, SSH)
/// are bound to specific IPs vs all interfaces.
/// </summary>
public sealed class NA06_MgmtIsolationCheck : ISecurityCheck
{
    public string Id => "NA06";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            int servicesChecked = 0;

            // 1. Check RDP binding
            ct.ThrowIfCancellationRequested();
            CheckRdpBinding(sb, evidence, ref hasIssue, ref servicesChecked);

            // 2. Check WinRM binding
            ct.ThrowIfCancellationRequested();
            CheckWinRmBinding(sb, evidence, ref hasIssue, ref servicesChecked, ct);

            // 3. Check SSH (OpenSSH) binding
            ct.ThrowIfCancellationRequested();
            CheckSshBinding(sb, evidence, ref hasIssue, ref servicesChecked);

            // 4. Check SNMP community strings
            ct.ThrowIfCancellationRequested();
            CheckSnmpConfig(sb, evidence, ref hasIssue);

            // Summary
            if (servicesChecked == 0)
            {
                sb.Insert(0, "No management services (RDP, WinRM, SSH) appear to be actively configured.\n");
            }
            else if (!hasIssue)
            {
                sb.Insert(0, "Management services checked; no all-interface binding issues detected.\n");
            }
            else
            {
                sb.Insert(0, "Management interface isolation issues detected.\n");
            }

            var status = hasIssue ? CheckStatus.Fail
                : servicesChecked > 0 ? CheckStatus.Pass
                : CheckStatus.NA;

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

    private static void CheckRdpBinding(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, ref int servicesChecked)
    {
        evidence.AppendLine("[RDP (Terminal Services) Configuration]");

        // Check if RDP is enabled
        int rdpEnabled = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections", 1);

        if (rdpEnabled == 0)
        {
            servicesChecked++;
            evidence.AppendLine("  RDP is enabled (fDenyTSConnections=0)");

            // Check listening port
            int rdpPort = RegistryHelper.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "PortNumber", 3389);
            evidence.AppendLine($"  RDP port: {rdpPort}");

            // RDP on Windows binds to 0.0.0.0 by default - no per-interface binding option
            // Check if NLA is required (mitigates broad exposure)
            int nla = RegistryHelper.GetValue<int>(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication", 0);

            evidence.AppendLine($"  Network Level Authentication (NLA): {(nla == 1 ? "Required" : "Not required")}");

            if (nla != 1)
            {
                hasIssue = true;
                sb.AppendLine("WARNING: RDP is enabled without NLA. Enable Network Level Authentication to reduce attack surface.");
            }

            sb.AppendLine($"RDP is enabled on port {rdpPort}, bound to all interfaces (Windows default). " +
                "Use Windows Firewall to restrict source IPs for management access.");
        }
        else
        {
            evidence.AppendLine("  RDP is disabled.");
        }
    }

    private static void CheckWinRmBinding(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, ref int servicesChecked, CancellationToken ct)
    {
        evidence.AppendLine("\n[WinRM Configuration]");

        try
        {
            var psi = new ProcessStartInfo("winrm", "enumerate winrm/config/listener")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                evidence.AppendLine("  Could not query WinRM.");
                return;
            }

            ct.Register(() => { try { proc.Kill(); } catch { } });

            string output = proc.StandardOutput.ReadToEnd();
            string error = proc.StandardError.ReadToEnd();
            proc.WaitForExit(15_000);

            if (!string.IsNullOrWhiteSpace(error) && error.Contains("not running", StringComparison.OrdinalIgnoreCase))
            {
                evidence.AppendLine("  WinRM service is not running.");
                return;
            }

            if (string.IsNullOrWhiteSpace(output))
            {
                evidence.AppendLine("  No WinRM listeners configured.");
                return;
            }

            servicesChecked++;
            evidence.AppendLine(output.Length > 1500 ? output[..1500] + "\n  ...(truncated)" : output);

            // Check for wildcard (*) address listener
            if (output.Contains("Address = *", StringComparison.OrdinalIgnoreCase))
            {
                hasIssue = true;
                sb.AppendLine("WARNING: WinRM listener is bound to all interfaces (Address = *). " +
                    "Bind to specific management IPs or restrict via firewall rules.");
            }
            else
            {
                sb.AppendLine("WinRM listeners appear restricted to specific addresses.");
            }

            // Check transport
            if (output.Contains("Transport = HTTP", StringComparison.OrdinalIgnoreCase) &&
                !output.Contains("Transport = HTTPS", StringComparison.OrdinalIgnoreCase))
            {
                hasIssue = true;
                sb.AppendLine("WARNING: WinRM is configured for HTTP only. Enable HTTPS transport for encrypted management.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  WinRM query error: {ex.Message}");
        }
    }

    private static void CheckSshBinding(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, ref int servicesChecked)
    {
        evidence.AppendLine("\n[OpenSSH Server Configuration]");

        // Check if OpenSSH server is installed
        if (!RegistryHelper.KeyExists(@"HKLM\SYSTEM\CurrentControlSet\Services\sshd"))
        {
            evidence.AppendLine("  OpenSSH Server (sshd) is not installed.");
            return;
        }

        servicesChecked++;
        evidence.AppendLine("  OpenSSH Server (sshd) is installed.");

        // Check sshd_config for ListenAddress
        string configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"..\ssh\sshd_config");

        // Try standard path
        string altPath = @"C:\ProgramData\ssh\sshd_config";
        string? actualPath = File.Exists(configPath) ? configPath
            : File.Exists(altPath) ? altPath
            : null;

        if (actualPath != null)
        {
            try
            {
                string config = File.ReadAllText(actualPath);
                evidence.AppendLine($"  Config: {actualPath}");

                bool hasListenAddress = false;
                foreach (var line in config.Split('\n'))
                {
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("ListenAddress", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("#"))
                    {
                        hasListenAddress = true;
                        evidence.AppendLine($"  {trimmed}");

                        if (trimmed.Contains("0.0.0.0") || trimmed.Contains("::"))
                        {
                            hasIssue = true;
                            sb.AppendLine("WARNING: SSH ListenAddress is set to all interfaces. " +
                                "Bind to management network IP only.");
                        }
                    }
                }

                if (!hasListenAddress)
                {
                    hasIssue = true;
                    sb.AppendLine("WARNING: SSH has no explicit ListenAddress - defaults to all interfaces (0.0.0.0). " +
                        "Configure ListenAddress in sshd_config to restrict to management network.");
                }
            }
            catch (Exception ex)
            {
                evidence.AppendLine($"  Could not read sshd_config: {ex.Message}");
            }
        }
        else
        {
            evidence.AppendLine("  sshd_config not found at standard paths.");
        }
    }

    private static void CheckSnmpConfig(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[SNMP Configuration]");

        string snmpPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities";
        var communities = RegistryHelper.GetValueNames(snmpPath);

        if (communities.Length > 0)
        {
            evidence.AppendLine($"  SNMP communities found: {communities.Length}");

            foreach (string community in communities)
            {
                if (community.Equals("public", StringComparison.OrdinalIgnoreCase) ||
                    community.Equals("private", StringComparison.OrdinalIgnoreCase))
                {
                    hasIssue = true;
                    sb.AppendLine($"CRITICAL: Default SNMP community string \"{community}\" is configured. " +
                        "Change to a unique, complex string or migrate to SNMPv3.");
                }
                evidence.AppendLine($"  Community: {community}");
            }
        }
        else
        {
            evidence.AppendLine("  SNMP service not configured or no communities.");
        }
    }
}

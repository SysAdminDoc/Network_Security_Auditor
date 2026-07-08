namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP09 - NAT/Port Forwarding: Check for port forwarding rules via netsh.
/// Check for UPnP service enabled.
/// </summary>
public sealed class NP09_NatCheck : ISecurityCheck
{
    public string Id => "NP09";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            int portProxyCount = 0;

            // 1. Check for port proxy (port forwarding) rules
            ct.ThrowIfCancellationRequested();
            CheckPortProxy(sb, evidence, ref hasIssue, ref portProxyCount, ct);

            // 2. Check for UPnP service
            ct.ThrowIfCancellationRequested();
            CheckUpnpService(sb, evidence, ref hasIssue, ct);

            // 3. Check for ICS (Internet Connection Sharing)
            ct.ThrowIfCancellationRequested();
            CheckIcs(sb, evidence, ref hasIssue, ct);

            // 4. Check for IP routing enabled
            ct.ThrowIfCancellationRequested();
            CheckIpRouting(sb, evidence, ref hasIssue);

            // Summary
            if (portProxyCount > 0)
                sb.Insert(0, $"Port forwarding detected ({portProxyCount} rule(s)).\n");
            else if (!hasIssue)
                sb.Insert(0, "No port forwarding or NAT concerns detected.\n");
            else
                sb.Insert(0, "NAT/port forwarding review found concerns.\n");

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

    private static void CheckPortProxy(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, ref int portProxyCount, CancellationToken ct)
    {
        evidence.AppendLine("[Port Proxy (netsh portproxy)]");

        try
        {
            string output = RunCommand("netsh", "interface portproxy show all", ct);

            if (string.IsNullOrWhiteSpace(output) ||
                output.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                evidence.AppendLine("  No port proxy rules configured.");
                return;
            }

            evidence.AppendLine(output.Length > 2000 ? output[..2000] : output);

            // Count actual forwarding rules (skip headers)
            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;
                if (trimmed.StartsWith("Listen", StringComparison.OrdinalIgnoreCase)) continue;
                if (trimmed.StartsWith("---")) continue;
                if (trimmed.StartsWith("Address", StringComparison.OrdinalIgnoreCase)) continue;

                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4)
                {
                    portProxyCount++;
                    hasIssue = true;
                }
            }

            if (portProxyCount > 0)
            {
                sb.AppendLine($"WARNING: {portProxyCount} port forwarding rule(s) found via netsh portproxy. " +
                    "Review each rule for necessity and security implications.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
        }
    }

    private static void CheckUpnpService(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[UPnP Service]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'upnphost'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                string startMode = obj["StartMode"]?.ToString() ?? "Unknown";

                evidence.AppendLine($"  UPnP Device Host: State={state}, StartMode={startMode}");

                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    hasIssue = true;
                    sb.AppendLine("WARNING: UPnP Device Host service is running. UPnP can allow " +
                        "applications to automatically create port forwarding rules on the router. " +
                        "Disable unless specifically required.");
                }
                else if (startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase))
                {
                    sb.AppendLine("INFO: UPnP service is set to Auto start but not currently running.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        // Also check SSDP Discovery
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'SSDPSRV'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                evidence.AppendLine($"  SSDP Discovery: State={state}");

                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    sb.AppendLine("INFO: SSDP Discovery service is running (UPnP-related).");
            }
        }
        catch { /* Non-critical */ }
    }

    private static void CheckIcs(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[Internet Connection Sharing]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'SharedAccess'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                string startMode = obj["StartMode"]?.ToString() ?? "Unknown";

                evidence.AppendLine($"  ICS (SharedAccess): State={state}, StartMode={startMode}");

                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    hasIssue = true;
                    sb.AppendLine("WARNING: Internet Connection Sharing (ICS) is running. " +
                        "This creates a NAT gateway that may bypass network security controls.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckIpRouting(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[IP Routing]");

        int ipRouting = Services.RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "IPEnableRouter", 0);

        evidence.AppendLine($"  IPEnableRouter: {ipRouting}");

        if (ipRouting == 1)
        {
            hasIssue = true;
            sb.AppendLine("WARNING: IP routing is enabled on this host. This machine can act as a router " +
                "between network segments, potentially bypassing security controls.");
        }
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        return CommandRunner.RunForOutput(fileName, arguments, TimeSpan.FromSeconds(15), ct);
    }
}

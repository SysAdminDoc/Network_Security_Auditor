namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NA04 - Network Documentation: Report adapter count, subnet info, gateway, DNS.
/// Checklist check that requires manual verification.
/// </summary>
public sealed class NA04_NetworkDocCheck : ISecurityCheck
{
    public string Id => "NA04";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int adapterCount = 0;

            evidence.AppendLine("[Network Configuration Summary for Documentation Review]");

            // Enumerate active adapters with config
            ct.ThrowIfCancellationRequested();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, " +
                    "DNSServerSearchOrder, DHCPEnabled, DNSDomain, MACAddress " +
                    "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();
                    adapterCount++;

                    string desc = obj["Description"]?.ToString() ?? "Unknown";
                    string[] ips = (obj["IPAddress"] as string[]) ?? [];
                    string[] subnets = (obj["IPSubnet"] as string[]) ?? [];
                    string[] gateways = (obj["DefaultIPGateway"] as string[]) ?? [];
                    string[] dns = (obj["DNSServerSearchOrder"] as string[]) ?? [];
                    bool dhcp = obj["DHCPEnabled"] is true;
                    string domain = obj["DNSDomain"]?.ToString() ?? "";
                    string mac = obj["MACAddress"]?.ToString() ?? "";

                    evidence.AppendLine($"\n  Adapter {adapterCount}: {desc}");
                    evidence.AppendLine($"    MAC: {mac}");
                    evidence.AppendLine($"    DHCP: {(dhcp ? "Enabled" : "Static")}");

                    for (int i = 0; i < ips.Length; i++)
                    {
                        string subnet = i < subnets.Length ? subnets[i] : "N/A";
                        evidence.AppendLine($"    IP: {ips[i]} / {subnet}");
                    }

                    evidence.AppendLine($"    Gateway: {(gateways.Length > 0 ? string.Join(", ", gateways) : "None")}");
                    evidence.AppendLine($"    DNS: {(dns.Length > 0 ? string.Join(", ", dns) : "None")}");
                    if (!string.IsNullOrEmpty(domain))
                        evidence.AppendLine($"    DNS Domain: {domain}");
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
            }

            sb.AppendLine($"Active network adapters detected: {adapterCount}.");
            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Network Documentation Review:");
            sb.AppendLine("  [ ] Network topology diagram exists and is current");
            sb.AppendLine("  [ ] IP address scheme is documented (subnets, VLANs, ranges)");
            sb.AppendLine("  [ ] Gateway and routing configuration is documented");
            sb.AppendLine("  [ ] DNS architecture is documented (internal/external, forwarders)");
            sb.AppendLine("  [ ] DHCP scopes and reservations are documented");
            sb.AppendLine("  [ ] Firewall zone architecture is documented");
            sb.AppendLine("  [ ] Network change management process exists");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Review network documentation " +
                "against the detected configuration above for accuracy and completeness.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
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

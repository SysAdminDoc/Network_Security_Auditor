namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Management;
using System.Net;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// CF06 - Network Flatness: Check IP subnet size, ARP table density.
/// Flag large subnets with many visible hosts.
/// </summary>
public sealed class CF06_NetworkFlatnessCheck : ISecurityCheck
{
    public string Id => "CF06";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Analyze subnet sizes from active adapters
            ct.ThrowIfCancellationRequested();
            var subnetInfo = AnalyzeSubnets(evidence, ct);

            // 2. Analyze ARP table density
            ct.ThrowIfCancellationRequested();
            int arpCount = AnalyzeArpDensity(evidence, ct);

            // 3. Correlate findings
            foreach (var (cidr, hostCapacity, ip) in subnetInfo)
            {
                if (cidr <= 16)
                {
                    hasIssue = true;
                    sb.AppendLine($"CRITICAL: Flat network indicator - {ip}/{cidr} subnet supports ~{hostCapacity:N0} hosts. " +
                        "This is an extremely large broadcast domain.");
                }
                else if (cidr <= 20)
                {
                    hasIssue = true;
                    sb.AppendLine($"WARNING: Large subnet {ip}/{cidr} (~{hostCapacity:N0} hosts). " +
                        "Consider micro-segmentation.");
                }
                else if (cidr <= 22)
                {
                    sb.AppendLine($"INFO: Subnet {ip}/{cidr} (~{hostCapacity:N0} hosts). " +
                        "Monitor for growth beyond /22.");
                }
            }

            if (arpCount > 200)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {arpCount} dynamic ARP entries indicate a large " +
                    "broadcast domain with many active hosts visible from this machine.");
            }
            else if (arpCount > 100)
            {
                sb.AppendLine($"INFO: {arpCount} dynamic ARP entries. Review if network segmentation is adequate.");
            }

            // Summary
            if (!hasIssue)
            {
                sb.Insert(0, $"Network flatness: Subnet sizes appear reasonable. {arpCount} ARP neighbors.\n");
            }
            else
            {
                sb.Insert(0, $"Network flatness issues detected. {arpCount} ARP neighbors.\n");
                sb.AppendLine("\nRecommendation: Implement VLANs, firewall zones, and " +
                    "micro-segmentation to limit lateral movement.");
            }

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

    private static List<(int Cidr, int HostCapacity, string Ip)> AnalyzeSubnets(
        StringBuilder evidence, CancellationToken ct)
    {
        var results = new List<(int, int, string)>();
        evidence.AppendLine("[Subnet Size Analysis]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT IPAddress, IPSubnet FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();

                string[] ips = (obj["IPAddress"] as string[]) ?? [];
                string[] subnets = (obj["IPSubnet"] as string[]) ?? [];

                for (int i = 0; i < ips.Length; i++)
                {
                    string ip = ips[i];
                    if (ip.Contains(':') || ip.StartsWith("169.254.")) continue;

                    string mask = i < subnets.Length ? subnets[i] : "255.255.255.0";
                    int cidr = SubnetMaskToCidr(mask);
                    int hostCapacity = (int)Math.Pow(2, 32 - cidr) - 2;

                    results.Add((cidr, hostCapacity, ip));
                    evidence.AppendLine($"  {ip}/{cidr} ({mask}) = ~{hostCapacity:N0} hosts");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        return results;
    }

    private static int AnalyzeArpDensity(StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[ARP Table Density]");
        int dynamicEntries = 0;

        try
        {
            string output = CommandRunner.RunForOutput("arp", "-a", TimeSpan.FromSeconds(15), ct);

            var subnetCounts = new Dictionary<string, int>();

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;
                if (!IPAddress.TryParse(parts[0], out _)) continue;
                if (!parts[2].Contains("dynamic", StringComparison.OrdinalIgnoreCase)) continue;

                dynamicEntries++;

                string subnet = string.Join('.', parts[0].Split('.').Take(3)) + ".0/24";
                subnetCounts.TryGetValue(subnet, out int count);
                subnetCounts[subnet] = count + 1;
            }

            evidence.AppendLine($"  Dynamic ARP entries: {dynamicEntries}");

            foreach (var (subnet, count) in subnetCounts.OrderByDescending(kv => kv.Value).Take(10))
                evidence.AppendLine($"  {subnet}: {count} neighbors");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  ARP error: {ex.Message}");
        }

        return dynamicEntries;
    }

    private static int SubnetMaskToCidr(string mask)
    {
        if (!IPAddress.TryParse(mask, out var ip)) return 24;

        int cidr = 0;
        foreach (byte b in ip.GetAddressBytes())
        {
            int val = b;
            while (val > 0)
            {
                cidr += val & 1;
                val >>= 1;
            }
        }
        return cidr;
    }
}

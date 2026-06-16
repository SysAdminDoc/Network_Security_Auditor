namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Diagnostics;
using System.Management;
using System.Net;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NA01 - Network segmentation indicators: adapter info, subnet sizing, ARP table analysis.
/// </summary>
public sealed class NA01_SegmentationCheck : ISecurityCheck
{
    public string Id => "NA01";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Network adapter configuration
            ct.ThrowIfCancellationRequested();
            var adapters = GetNetworkAdapters(evidence, ct);

            // 2. Analyze subnet sizes
            ct.ThrowIfCancellationRequested();
            AnalyzeSubnets(adapters, sb, evidence, ref hasIssue);

            // 3. ARP table analysis
            ct.ThrowIfCancellationRequested();
            AnalyzeArpTable(sb, evidence, ref hasIssue, ct);

            // 4. DNS configuration check
            ct.ThrowIfCancellationRequested();
            CheckDnsConfig(adapters, sb, evidence);

            if (!hasIssue)
                sb.Insert(0, "Network segmentation appears adequate based on local indicators.\n");

            var status = hasIssue ? CheckStatus.Partial : CheckStatus.Pass;

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

    private static List<AdapterInfo> GetNetworkAdapters(StringBuilder evidence, CancellationToken ct)
    {
        var adapters = new List<AdapterInfo>();
        evidence.AppendLine("[Network Adapter Configuration]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, MACAddress " +
                "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();

                string desc = obj["Description"]?.ToString() ?? "Unknown";
                string[] ips = (obj["IPAddress"] as string[]) ?? [];
                string[] subnets = (obj["IPSubnet"] as string[]) ?? [];
                string[] gateways = (obj["DefaultIPGateway"] as string[]) ?? [];
                string[] dns = (obj["DNSServerSearchOrder"] as string[]) ?? [];
                string mac = obj["MACAddress"]?.ToString() ?? "";

                var adapter = new AdapterInfo
                {
                    Description = desc,
                    IPAddresses = ips,
                    SubnetMasks = subnets,
                    Gateways = gateways,
                    DnsServers = dns,
                    MacAddress = mac
                };

                adapters.Add(adapter);

                evidence.AppendLine($"\n  Adapter: {desc}");
                evidence.AppendLine($"    MAC: {mac}");
                for (int i = 0; i < ips.Length; i++)
                {
                    string subnet = i < subnets.Length ? subnets[i] : "N/A";
                    evidence.AppendLine($"    IP: {ips[i]} / {subnet}");
                }
                evidence.AppendLine($"    Gateway: {(gateways.Length > 0 ? string.Join(", ", gateways) : "None")}");
                evidence.AppendLine($"    DNS: {(dns.Length > 0 ? string.Join(", ", dns) : "None")}");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        return adapters;
    }

    private static void AnalyzeSubnets(List<AdapterInfo> adapters, StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[Subnet Analysis]");

        foreach (var adapter in adapters)
        {
            for (int i = 0; i < adapter.IPAddresses.Length; i++)
            {
                string ip = adapter.IPAddresses[i];

                // Skip IPv6 and link-local
                if (ip.Contains(':')) continue;
                if (ip.StartsWith("169.254.")) continue;

                string mask = i < adapter.SubnetMasks.Length ? adapter.SubnetMasks[i] : "255.255.255.0";

                int cidr = SubnetMaskToCidr(mask);
                int hostCount = (int)Math.Pow(2, 32 - cidr) - 2;

                evidence.AppendLine($"  {ip}/{cidr} ({mask}) = ~{hostCount} hosts");

                if (cidr <= 16)
                {
                    hasIssue = true;
                    sb.AppendLine($"WARNING: Flat network indicator - {ip}/{cidr} subnet has ~{hostCount:N0} possible hosts.");
                    sb.AppendLine("  A /{cidr} or larger subnet suggests limited network segmentation.");
                    sb.AppendLine("  Recommend micro-segmentation with VLANs and firewall zones.");
                }
                else if (cidr <= 20)
                {
                    sb.AppendLine($"INFO: Large subnet {ip}/{cidr} (~{hostCount:N0} hosts). Consider whether segmentation is adequate.");
                }
            }
        }
    }

    private static void AnalyzeArpTable(StringBuilder sb, StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[ARP Table Analysis]");

        try
        {
            string output = RunCommand("arp", "-a", ct);

            int totalEntries = 0;
            int dynamicEntries = 0;
            var subnetsWithHosts = new Dictionary<string, int>();

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();

                // Parse ARP entries: IP  MAC  Type
                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                if (!IPAddress.TryParse(parts[0], out var ip)) continue;

                totalEntries++;
                if (parts[2].Contains("dynamic", StringComparison.OrdinalIgnoreCase))
                    dynamicEntries++;

                // Group by /24 subnet for density analysis
                string subnet = string.Join('.', parts[0].Split('.').Take(3)) + ".0/24";
                subnetsWithHosts.TryGetValue(subnet, out int count);
                subnetsWithHosts[subnet] = count + 1;
            }

            evidence.AppendLine($"  Total ARP entries: {totalEntries}");
            evidence.AppendLine($"  Dynamic entries: {dynamicEntries}");

            foreach (var (subnet, count) in subnetsWithHosts.OrderByDescending(kv => kv.Value))
            {
                evidence.AppendLine($"  Subnet {subnet}: {count} neighbors");
            }

            // High neighbor count in a single /24 is normal, but across many /24s = flat
            if (subnetsWithHosts.Count > 5)
            {
                sb.AppendLine($"INFO: ARP table spans {subnetsWithHosts.Count} distinct /24 subnets. Verify this is expected topology.");
            }

            if (dynamicEntries > 200)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {dynamicEntries} dynamic ARP entries suggest a large broadcast domain / flat network.");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  ARP query error: {ex.Message}");
        }
    }

    private static void CheckDnsConfig(List<AdapterInfo> adapters, StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[DNS Configuration]");

        var allDns = adapters
            .SelectMany(a => a.DnsServers)
            .Distinct()
            .ToList();

        evidence.AppendLine($"  Unique DNS servers: {string.Join(", ", allDns)}");

        // Check for well-known public DNS (possible split-horizon bypass)
        var publicDns = new HashSet<string> { "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9" };
        var foundPublic = allDns.Where(d => publicDns.Contains(d)).ToList();

        if (foundPublic.Count > 0)
        {
            sb.AppendLine($"INFO: Public DNS servers configured ({string.Join(", ", foundPublic)}). " +
                "If this is a domain-joined machine, internal DNS should be primary.");
        }
    }

    private static int SubnetMaskToCidr(string mask)
    {
        if (!IPAddress.TryParse(mask, out var ip)) return 24;

        byte[] bytes = ip.GetAddressBytes();
        int cidr = 0;
        foreach (byte b in bytes)
        {
            // Count set bits
            int val = b;
            while (val > 0)
            {
                cidr += val & 1;
                val >>= 1;
            }
        }
        return cidr;
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

    private sealed class AdapterInfo
    {
        public string Description { get; init; } = "";
        public string[] IPAddresses { get; init; } = [];
        public string[] SubnetMasks { get; init; } = [];
        public string[] Gateways { get; init; } = [];
        public string[] DnsServers { get; init; } = [];
        public string MacAddress { get; init; } = "";
    }
}

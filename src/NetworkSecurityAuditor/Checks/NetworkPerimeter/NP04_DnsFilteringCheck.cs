namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Net;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP04 - DNS Filtering: Check DNS server addresses, test resolution of known malware
/// domains (if NoInternet not set), check for known filtering DNS providers.
/// </summary>
public sealed class NP04_DnsFilteringCheck : ISecurityCheck
{
    public string Id => "NP04";

    private static readonly Dictionary<string, string> KnownFilteringDns = new()
    {
        { "208.67.222.222", "OpenDNS/Cisco Umbrella" },
        { "208.67.220.220", "OpenDNS/Cisco Umbrella" },
        { "9.9.9.9", "Quad9" },
        { "149.112.112.112", "Quad9" },
        { "1.1.1.2", "Cloudflare (Malware)" },
        { "1.0.0.2", "Cloudflare (Malware)" },
        { "1.1.1.3", "Cloudflare (Malware+Adult)" },
        { "1.0.0.3", "Cloudflare (Malware+Adult)" },
        { "185.228.168.168", "CleanBrowsing" },
        { "185.228.169.168", "CleanBrowsing" },
        { "76.76.2.0", "Control D" },
        { "76.76.10.0", "Control D" },
    };

    // Test domains that known filtering DNS should block
    private static readonly string[] TestMalwareDomains =
    [
        "malware.testcategory.com",
        "examplemalwaredomain.com",
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasFiltering = false;
            bool hasWarning = false;

            // 1. Enumerate DNS servers
            ct.ThrowIfCancellationRequested();
            var dnsServers = GetDnsServers(evidence, ct);

            // 2. Check for known filtering DNS
            evidence.AppendLine("\n[Known Filtering DNS Check]");

            foreach (string dns in dnsServers)
            {
                if (KnownFilteringDns.TryGetValue(dns, out string? provider))
                {
                    hasFiltering = true;
                    sb.AppendLine($"Filtering DNS detected: {dns} ({provider})");
                    evidence.AppendLine($"  {dns} -> {provider}");
                }
            }

            // 3. Check for NextDNS (uses custom IPs per account)
            CheckNextDns(dnsServers, sb, evidence, ref hasFiltering);

            // 4. Check DNS-over-HTTPS registry settings
            ct.ThrowIfCancellationRequested();
            CheckDohSettings(sb, evidence);

            // 5. Test malware domain resolution if internet is available
            if (!options.NoInternet)
            {
                ct.ThrowIfCancellationRequested();
                TestMalwareDomainResolution(sb, evidence, ref hasFiltering);
            }
            else
            {
                evidence.AppendLine("\n[DNS Resolution Test]");
                evidence.AppendLine("  Skipped (NoInternet flag set).");
            }

            // Summary
            if (hasFiltering)
            {
                sb.Insert(0, "DNS filtering is configured.\n");
            }
            else
            {
                hasWarning = true;
                sb.Insert(0, "No DNS filtering detected.\n");
                sb.AppendLine("WARNING: No known DNS filtering provider detected. " +
                    "Recommend implementing DNS-based threat protection " +
                    "(Cisco Umbrella, Quad9, Cloudflare for Teams, NextDNS, etc.).");
            }

            var status = hasFiltering ? CheckStatus.Pass
                : hasWarning ? CheckStatus.Fail
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

    private static List<string> GetDnsServers(StringBuilder evidence, CancellationToken ct)
    {
        var servers = new List<string>();
        evidence.AppendLine("[DNS Server Configuration]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DNSServerSearchOrder, Description FROM Win32_NetworkAdapterConfiguration " +
                "WHERE IPEnabled = TRUE");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string desc = obj["Description"]?.ToString() ?? "Unknown";
                string[] dns = (obj["DNSServerSearchOrder"] as string[]) ?? [];

                if (dns.Length > 0)
                {
                    evidence.AppendLine($"  {desc}: {string.Join(", ", dns)}");
                    servers.AddRange(dns);
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        return servers.Distinct().ToList();
    }

    private static void CheckNextDns(List<string> dnsServers, StringBuilder sb,
        StringBuilder evidence, ref bool hasFiltering)
    {
        // NextDNS uses 45.90.28.x and 45.90.30.x ranges
        foreach (string dns in dnsServers)
        {
            if (dns.StartsWith("45.90.28.") || dns.StartsWith("45.90.30."))
            {
                hasFiltering = true;
                sb.AppendLine($"NextDNS filtering detected: {dns}");
                evidence.AppendLine($"  {dns} -> NextDNS (custom profile)");
            }
        }
    }

    private static void CheckDohSettings(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[DNS-over-HTTPS (DoH) Settings]");

        // Windows 11 DoH settings
        int dohEnabled = Services.RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "EnableAutoDoh", -1);

        if (dohEnabled >= 0)
        {
            evidence.AppendLine($"  EnableAutoDoh: {dohEnabled}");
            if (dohEnabled == 2)
                sb.AppendLine("INFO: DNS-over-HTTPS is enabled (auto-upgrade mode).");
        }
        else
        {
            evidence.AppendLine("  DoH registry setting not found (default behavior).");
        }
    }

    private static void TestMalwareDomainResolution(StringBuilder sb, StringBuilder evidence,
        ref bool hasFiltering)
    {
        evidence.AppendLine("\n[DNS Resolution Test]");

        foreach (string domain in TestMalwareDomains)
        {
            try
            {
                var result = Dns.GetHostAddresses(domain);
                if (result.Length > 0)
                {
                    string resolved = string.Join(", ", result.Select(a => a.ToString()));
                    evidence.AppendLine($"  {domain} -> {resolved}");

                    // Check if resolved to a sinkhole/block page (common patterns)
                    foreach (var addr in result)
                    {
                        string ip = addr.ToString();
                        if (ip is "0.0.0.0" or "127.0.0.1" or "::1" ||
                            ip.StartsWith("146.112.") || // Cisco Umbrella block
                            ip.StartsWith("::ffff:0.0.0.0"))
                        {
                            hasFiltering = true;
                            evidence.AppendLine($"    -> Sinkhole/block response detected");
                        }
                    }
                }
            }
            catch (Exception)
            {
                // NXDOMAIN or failure = domain is blocked or doesn't exist (expected)
                evidence.AppendLine($"  {domain} -> NXDOMAIN/blocked");
            }
        }
    }
}

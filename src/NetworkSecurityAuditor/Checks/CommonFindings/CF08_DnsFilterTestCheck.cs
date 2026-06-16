namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Net;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF08 - DNS Filtering Test: Test DNS resolution of known malware domains.
/// If NoInternet, skip. Risk tier: Probing.
/// </summary>
public sealed class CF08_DnsFilterTestCheck : ISecurityCheck
{
    public string Id => "CF08";

    // Known test domains used by DNS filtering services
    private static readonly (string Domain, string Category)[] TestDomains =
    [
        ("malware.testcategory.com", "Malware"),
        ("examplemalwaredomain.com", "Malware"),
        ("internetbadguys.com", "Cisco Umbrella Test"),
        ("phishing.testcategory.com", "Phishing"),
    ];

    // Known sinkhole/block IPs
    private static readonly HashSet<string> SinkholeIps =
    [
        "0.0.0.0", "127.0.0.1", "::1", "::ffff:0.0.0.0",
    ];

    private static readonly string[] SinkholePrefixes =
    [
        "146.112.", // Cisco Umbrella
        "0.0.0.",
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (options.NoInternet)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "DNS filtering test skipped (NoInternet flag is set).",
                Evidence = $"NoInternet=true @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int tested = 0;
            int blocked = 0;
            int resolved = 0;

            evidence.AppendLine("[DNS Filtering Test]");

            foreach (var (domain, category) in TestDomains)
            {
                ct.ThrowIfCancellationRequested();
                tested++;

                try
                {
                    var addresses = Dns.GetHostAddresses(domain);

                    if (addresses.Length == 0)
                    {
                        blocked++;
                        evidence.AppendLine($"  {domain} ({category}): No addresses returned (blocked)");
                        continue;
                    }

                    string resolvedIps = string.Join(", ", addresses.Select(a => a.ToString()));
                    evidence.AppendLine($"  {domain} ({category}): Resolved to {resolvedIps}");

                    // Check if resolved to sinkhole
                    bool isSinkholed = false;
                    foreach (var addr in addresses)
                    {
                        string ip = addr.ToString();
                        if (SinkholeIps.Contains(ip) ||
                            SinkholePrefixes.Any(p => ip.StartsWith(p)))
                        {
                            isSinkholed = true;
                            break;
                        }
                    }

                    if (isSinkholed)
                    {
                        blocked++;
                        evidence.AppendLine($"    -> Sinkhole response (DNS filtering active)");
                    }
                    else
                    {
                        resolved++;
                    }
                }
                catch (Exception)
                {
                    // NXDOMAIN = domain blocked or doesn't exist
                    blocked++;
                    evidence.AppendLine($"  {domain} ({category}): NXDOMAIN/Error (likely blocked)");
                }
            }

            sb.AppendLine($"DNS filtering test: {tested} domains tested, {blocked} blocked, {resolved} resolved.");

            if (resolved > 0)
            {
                sb.AppendLine($"\nWARNING: {resolved} known malware/test domain(s) resolved successfully. " +
                    "DNS filtering may not be active or properly configured.");
                sb.AppendLine("Recommendation: Deploy DNS-based threat protection " +
                    "(Cisco Umbrella, Quad9, Cloudflare Gateway, NextDNS).");
            }

            if (blocked > 0 && resolved == 0)
            {
                sb.AppendLine("PASS: All test domains were blocked by DNS filtering.");
            }
            else if (blocked > 0)
            {
                sb.AppendLine($"PARTIAL: {blocked} domain(s) blocked but {resolved} resolved. " +
                    "DNS filtering may have gaps.");
            }

            var status = resolved == 0 && blocked > 0 ? CheckStatus.Pass
                : blocked > 0 ? CheckStatus.Partial
                : CheckStatus.Fail;

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
}

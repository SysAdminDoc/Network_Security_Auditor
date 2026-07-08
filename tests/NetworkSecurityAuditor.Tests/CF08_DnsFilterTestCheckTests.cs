using System.Net;
using System.Net.Sockets;
using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CF08_DnsFilterTestCheckTests
{
    [Fact]
    public async Task ExecuteAsync_Returns_NA_When_Control_Domain_Fails()
    {
        var check = new CF08_DnsFilterTestCheck(_ => throw new SocketException());

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.NA, result.Status);
        Assert.Contains("control domain", result.Findings, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Control lookup failed", result.Evidence);
    }

    [Fact]
    public async Task ExecuteAsync_Passes_When_Known_Valid_Test_Domains_Are_Blocked()
    {
        static IPAddress[] Resolve(string domain)
        {
            if (domain == "example.com") return new[] { IPAddress.Parse("93.184.216.34") };
            throw new SocketException();
        }

        var check = new CF08_DnsFilterTestCheck(Resolve);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("3 domains tested, 3 blocked, 0 resolved", result.Findings);
        Assert.Contains("known-valid test domain", result.Evidence);
    }

    [Fact]
    public async Task ExecuteAsync_Fails_When_No_Test_Domains_Are_Filtered()
    {
        var check = new CF08_DnsFilterTestCheck(_ => new[] { IPAddress.Parse("203.0.113.10") });

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("3 known malware/test domain(s) resolved successfully", result.Findings);
    }
}

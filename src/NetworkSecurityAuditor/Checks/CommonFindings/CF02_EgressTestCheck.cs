namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Net.Sockets;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF02 - Egress Filtering Test: If NoInternet not set, test outbound connectivity
/// on high-risk ports (25, 445, 3389, 1433, etc.) to known targets.
/// Risk tier: Probing.
/// </summary>
public sealed class CF02_EgressTestCheck : ISecurityCheck
{
    private const string EgressTestHost = "portquiz.net";
    private const int ControlPort = 80;
    private readonly Func<string, int, TimeSpan, bool> _tcpConnect;

    public string Id => "CF02";

    // Ports that should typically be blocked outbound from workstations
    private static readonly (int Port, string Service)[] EgressTests =
    [
        (25, "SMTP"),
        (445, "SMB"),
        (1433, "MSSQL"),
        (3389, "RDP"),
        (23, "Telnet"),
        (21, "FTP"),
        (5900, "VNC"),
        (4444, "Metasploit Default"),
        (8080, "HTTP Proxy"),
    ];

    public CF02_EgressTestCheck(Func<string, int, TimeSpan, bool>? tcpConnect = null)
    {
        _tcpConnect = tcpConnect ?? TestTcpConnect;
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (options.NoInternet)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Egress filtering test skipped (NoInternet flag is set).",
                Evidence = $"NoInternet=true @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int openPorts = 0;
            int blockedPorts = 0;
            int testedPorts = 0;
            var openPortList = new List<string>();

            var timeout = TimeSpan.FromSeconds(3);
            evidence.AppendLine("[Egress Filtering Test]");
            evidence.AppendLine($"  Test method: TCP connect to {EgressTestHost} with {timeout.TotalSeconds:0}-second timeout");
            evidence.AppendLine($"  Control: {EgressTestHost}:{ControlPort}");

            if (!_tcpConnect(EgressTestHost, ControlPort, timeout))
            {
                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.NA,
                    Findings = "Egress filtering test could not reach the control port on the outbound test service. Filtering cannot be confirmed.",
                    Evidence = evidence.AppendLine("  Control connection failed; high-risk port results not attempted.").ToString().TrimEnd()
                });
            }

            evidence.AppendLine("  Control connection succeeded; high-risk port failures are counted as filtered.");

            foreach (var (port, service) in EgressTests)
            {
                ct.ThrowIfCancellationRequested();
                testedPorts++;

                bool reachable = _tcpConnect(EgressTestHost, port, timeout);

                if (reachable)
                {
                    openPorts++;
                    openPortList.Add($"{port} ({service})");
                    evidence.AppendLine($"  OPEN: {EgressTestHost}:{port} ({service}) - outbound connection succeeded");
                }
                else
                {
                    blockedPorts++;
                    evidence.AppendLine($"  BLOCKED: {EgressTestHost}:{port} ({service}) - expected listener was unreachable");
                }
            }

            sb.AppendLine($"Egress test: {testedPorts} ports tested, {openPorts} open, {blockedPorts} blocked.");

            if (openPorts > 0)
            {
                sb.AppendLine($"\nWARNING: {openPorts} high-risk port(s) are reachable outbound:");
                foreach (string p in openPortList)
                    sb.AppendLine($"  - Port {p}");

                sb.AppendLine("\nRecommendation: Implement outbound firewall rules to block unnecessary " +
                    "egress traffic. Malware commonly uses these ports for C2 communication and data exfiltration.");
            }
            else
            {
                sb.AppendLine("PASS: All tested high-risk ports appear to be blocked outbound.");
            }

            var status = openPorts > 3 ? CheckStatus.Fail
                : openPorts > 0 ? CheckStatus.Partial
                : CheckStatus.Pass;

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

    private static bool TestTcpConnect(string host, int port, TimeSpan timeout)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            return connectTask.Wait(timeout);
        }
        catch
        {
            return false;
        }
    }
}

namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP02 - Open Ports Audit: Find listening TCP ports via netstat. Flag high-risk ports
/// (21, 23, 69, 135, 139, 445, 1433, 3389, 5900).
/// </summary>
public sealed class NP02_OpenPortsCheck : ISecurityCheck
{
    public string Id => "NP02";

    private static readonly Dictionary<int, string> HighRiskPorts = new()
    {
        { 21, "FTP" },
        { 23, "Telnet" },
        { 69, "TFTP" },
        { 135, "RPC/DCOM" },
        { 139, "NetBIOS" },
        { 445, "SMB" },
        { 1433, "MSSQL" },
        { 1434, "MSSQL Browser" },
        { 3389, "RDP" },
        { 5900, "VNC" },
        { 5985, "WinRM HTTP" },
        { 5986, "WinRM HTTPS" },
        { 8080, "HTTP Proxy/Alt" },
        { 8443, "HTTPS Alt" },
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasHighRisk = false;
            int totalListening = 0;
            var highRiskFound = new List<(int Port, string Service, string Address)>();

            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Listening TCP Ports]");

            try
            {
                string output = RunCommand("netstat", "-an", ct);

                foreach (var line in output.Split('\n'))
                {
                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!trimmed.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;

                    var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3) continue;

                    string localAddr = parts[1];
                    int lastColon = localAddr.LastIndexOf(':');
                    if (lastColon < 0) continue;

                    if (!int.TryParse(localAddr[(lastColon + 1)..], out int port)) continue;
                    string bindAddr = localAddr[..lastColon];

                    totalListening++;
                    evidence.AppendLine($"  {localAddr} LISTENING");

                    if (HighRiskPorts.TryGetValue(port, out string? service))
                    {
                        hasHighRisk = true;
                        highRiskFound.Add((port, service, bindAddr));
                    }
                }
            }
            catch (Exception ex)
            {
                evidence.AppendLine($"  netstat error: {ex.Message}");
            }

            sb.AppendLine($"Total listening TCP ports: {totalListening}.");

            if (highRiskFound.Count > 0)
            {
                sb.AppendLine($"\nHigh-risk ports listening ({highRiskFound.Count}):");
                foreach (var (port, service, addr) in highRiskFound.OrderBy(p => p.Port))
                {
                    string bindNote = addr is "0.0.0.0" or "[::]" ? " (ALL interfaces)" : $" ({addr})";
                    sb.AppendLine($"  Port {port} ({service}){bindNote}");
                }

                sb.AppendLine("\nRecommendation: Review each high-risk port. Disable unnecessary services, " +
                    "restrict with firewall rules, or migrate to encrypted alternatives (e.g., SFTP over FTP, SSH over Telnet).");
            }
            else if (totalListening > 0)
            {
                sb.AppendLine("PASS: No high-risk ports detected among listening services.");
            }

            if (totalListening > 30)
            {
                sb.AppendLine($"WARNING: {totalListening} listening ports is a large attack surface. " +
                    "Review for unnecessary services.");
            }

            var status = hasHighRisk ? CheckStatus.Fail : CheckStatus.Pass;

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

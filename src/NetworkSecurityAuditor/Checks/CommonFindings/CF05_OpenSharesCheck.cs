namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Diagnostics;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF05 - Open Shares: Enumerate local SMB shares. Check share permissions for
/// Everyone/Authenticated Users access.
/// </summary>
public sealed class CF05_OpenSharesCheck : ISecurityCheck
{
    public string Id => "CF05";

    private static readonly string[] BroadAccessPrincipals =
    [
        "Everyone", "Authenticated Users", "ANONYMOUS LOGON", "Users"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            int totalShares = 0;
            int openShares = 0;

            // 1. Enumerate shares via WMI
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Local SMB Shares]");

            var shares = new List<(string Name, string Path, uint Type)>();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Path, Type FROM Win32_Share");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();

                    string name = obj["Name"]?.ToString() ?? "";
                    string path = obj["Path"]?.ToString() ?? "";
                    uint type = Convert.ToUInt32(obj["Type"] ?? 0);

                    totalShares++;
                    shares.Add((name, path, type));

                    string typeStr = type switch
                    {
                        0 => "Disk",
                        1 => "Printer",
                        2 => "Device",
                        3 => "IPC",
                        0x80000000 => "Admin (Disk)",
                        0x80000001 => "Admin (Printer)",
                        0x80000002 => "Admin (Device)",
                        0x80000003 => "Admin (IPC)",
                        _ => $"Type={type}"
                    };

                    evidence.AppendLine($"  {name} -> {path} [{typeStr}]");
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
            }

            // 2. Check share permissions via WMI
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Share Permissions]");

            foreach (var (name, path, type) in shares)
            {
                // Skip admin shares (C$, ADMIN$, IPC$)
                if (name.EndsWith('$')) continue;

                ct.ThrowIfCancellationRequested();
                CheckSharePermissions(name, sb, evidence, ref hasIssue, ref openShares, ct);
            }

            // 3. Check if SMB1 is enabled
            ct.ThrowIfCancellationRequested();
            CheckSmb1(sb, evidence, ref hasIssue);

            sb.Insert(0, $"Local shares: {totalShares} total, {openShares} with broad access permissions.\n");

            if (!hasIssue && openShares == 0)
                sb.AppendLine("PASS: No non-admin shares with overly broad access detected.");

            var status = hasIssue ? CheckStatus.Fail
                : openShares > 0 ? CheckStatus.Partial
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

    private static void CheckSharePermissions(string shareName, StringBuilder sb,
        StringBuilder evidence, ref bool hasIssue, ref int openShares, CancellationToken ct)
    {
        try
        {
            // Use net share command to get permissions
            var psi = new ProcessStartInfo("net", $"share \"{shareName}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;

            ct.Register(() => { try { proc.Kill(); } catch { } });

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);

            bool inPermissions = false;
            evidence.AppendLine($"\n  Share: {shareName}");

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();

                if (trimmed.StartsWith("Permission", StringComparison.OrdinalIgnoreCase))
                {
                    inPermissions = true;
                    continue;
                }

                if (inPermissions && !string.IsNullOrWhiteSpace(trimmed))
                {
                    if (trimmed.StartsWith("The command", StringComparison.OrdinalIgnoreCase))
                        break;

                    evidence.AppendLine($"    {trimmed}");

                    // Check for broad access
                    foreach (string broad in BroadAccessPrincipals)
                    {
                        if (trimmed.Contains(broad, StringComparison.OrdinalIgnoreCase))
                        {
                            bool hasFullControl = trimmed.Contains("FULL", StringComparison.OrdinalIgnoreCase);
                            bool hasChange = trimmed.Contains("CHANGE", StringComparison.OrdinalIgnoreCase);

                            if (hasFullControl || hasChange)
                            {
                                hasIssue = true;
                                openShares++;
                                string access = hasFullControl ? "Full Control" : "Change";
                                sb.AppendLine($"CRITICAL: Share \"{shareName}\" grants {access} to {broad}.");
                            }
                            else
                            {
                                openShares++;
                                sb.AppendLine($"WARNING: Share \"{shareName}\" grants Read to {broad}.");
                            }
                            break;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"    Error checking permissions: {ex.Message}");
        }
    }

    private static void CheckSmb1(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[SMB1 Protocol Check]");

        int smb1Enabled = Services.RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1", -1);

        evidence.AppendLine($"  SMB1 registry value: {smb1Enabled}");

        if (smb1Enabled == 1)
        {
            hasIssue = true;
            sb.AppendLine("CRITICAL: SMB1 protocol is explicitly enabled. Disable SMB1 to prevent " +
                "EternalBlue-class vulnerabilities.");
        }
    }
}

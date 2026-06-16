namespace NetworkSecurityAuditor.Checks.CommonFindings;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// CF07 - Enumerate local Administrators group. Flag overly broad members
///        (Domain Users, Everyone, Authenticated Users).
/// </summary>
public sealed class CF07_LocalAdminRightsCheck : ISecurityCheck
{
    public string Id => "CF07";

    private static readonly string[] OverlyBroadPrincipals =
    [
        "Domain Users",
        "Everyone",
        "Authenticated Users",
        "Users",
        "Domain Computers",
        "Domain Guests",
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasCritical = false;
            bool hasWarning = false;

            evidence.AppendLine("[Local Administrators Group Members]");

            var members = new List<string>();

            ct.ThrowIfCancellationRequested();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT GroupComponent, PartComponent FROM Win32_GroupUser");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();

                    string group = obj["GroupComponent"]?.ToString() ?? "";
                    string member = obj["PartComponent"]?.ToString() ?? "";

                    if (!group.Contains("\"Administrators\"", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string accountName = ExtractAccountName(member);
                    members.Add(accountName);
                    evidence.AppendLine($"  {accountName}");
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI Error: {ex.Message}");

                // Fallback: try net localgroup
                FallbackNetLocalGroup(members, evidence, ct);
            }

            if (members.Count == 0)
            {
                sb.AppendLine("Could not enumerate Administrators group members.");
                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.NA,
                    Findings = sb.ToString().TrimEnd(),
                    Evidence = evidence.ToString().TrimEnd()
                });
            }

            sb.AppendLine($"Local Administrators group: {members.Count} member(s).");

            // Check for overly broad principals
            foreach (string broad in OverlyBroadPrincipals)
            {
                var match = members.FirstOrDefault(m =>
                    m.EndsWith($"\\{broad}", StringComparison.OrdinalIgnoreCase) ||
                    m.Equals(broad, StringComparison.OrdinalIgnoreCase));

                if (match is not null)
                {
                    hasCritical = true;
                    sb.AppendLine($"CRITICAL: '{match}' is in local Administrators. This grants admin rights to a broad population.");
                }
            }

            // Check member count
            if (members.Count > 5)
            {
                hasWarning = true;
                sb.AppendLine($"WARNING: {members.Count} members in Administrators is excessive. Principle of least privilege recommends fewer.");
            }

            // Check for enabled built-in Administrator account
            ct.ThrowIfCancellationRequested();
            CheckBuiltInAdmin(sb, evidence, ref hasWarning);

            // Check for Guest account status
            ct.ThrowIfCancellationRequested();
            CheckGuestAccount(sb, evidence, ref hasWarning);

            if (!hasCritical && !hasWarning)
                sb.AppendLine("PASS: No overly broad principals in Administrators group.");

            var status = hasCritical ? CheckStatus.Fail
                : hasWarning ? CheckStatus.Partial
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

    private static void CheckBuiltInAdmin(StringBuilder sb, StringBuilder evidence, ref bool hasWarning)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, Disabled, SID FROM Win32_UserAccount WHERE LocalAccount = TRUE");

            evidence.AppendLine("\n[Built-in Account Status]");
            foreach (ManagementObject obj in searcher.Get())
            {
                string sid = obj["SID"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";
                bool disabled = obj["Disabled"] is true;

                // Built-in Administrator: SID ends in -500
                if (sid.EndsWith("-500"))
                {
                    evidence.AppendLine($"  Administrator ({name}): Disabled={disabled}, SID={sid}");
                    if (!disabled)
                    {
                        hasWarning = true;
                        sb.AppendLine($"WARNING: Built-in Administrator account '{name}' is enabled. Consider disabling or renaming.");
                    }
                }

                // Guest: SID ends in -501
                if (sid.EndsWith("-501"))
                {
                    evidence.AppendLine($"  Guest ({name}): Disabled={disabled}, SID={sid}");
                }
            }
        }
        catch
        {
            evidence.AppendLine("  Could not query local user accounts.");
        }
    }

    private static void CheckGuestAccount(StringBuilder sb, StringBuilder evidence, ref bool hasWarning)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE '%-501'");

            foreach (ManagementObject obj in searcher.Get())
            {
                bool disabled = obj["Disabled"] is true;
                string name = obj["Name"]?.ToString() ?? "Guest";

                if (!disabled)
                {
                    hasWarning = true;
                    sb.AppendLine($"WARNING: Guest account '{name}' is enabled. This should be disabled per CIS benchmarks.");
                }
            }
        }
        catch
        {
            // Already captured in built-in admin check
        }
    }

    private static void FallbackNetLocalGroup(List<string> members, StringBuilder evidence, CancellationToken ct)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("net", "localgroup Administrators")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null) return;

            ct.Register(() => { try { proc.Kill(); } catch { } });

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);

            evidence.AppendLine("\n  [Fallback: net localgroup]");
            bool inMembers = false;
            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("---"))
                {
                    inMembers = true;
                    continue;
                }
                if (trimmed.StartsWith("The command completed")) break;

                if (inMembers && !string.IsNullOrWhiteSpace(trimmed))
                {
                    members.Add(trimmed);
                    evidence.AppendLine($"  {trimmed}");
                }
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  net localgroup fallback error: {ex.Message}");
        }
    }

    private static string ExtractAccountName(string wmiPath)
    {
        try
        {
            int nameIdx = wmiPath.IndexOf("Name=\"", StringComparison.OrdinalIgnoreCase);
            if (nameIdx < 0) return wmiPath;
            int start = nameIdx + 6;
            int end = wmiPath.IndexOf('"', start);
            string name = end > start ? wmiPath[start..end] : wmiPath[start..];

            int domIdx = wmiPath.IndexOf("Domain=\"", StringComparison.OrdinalIgnoreCase);
            if (domIdx >= 0)
            {
                int dStart = domIdx + 8;
                int dEnd = wmiPath.IndexOf('"', dStart);
                string domain = dEnd > dStart ? wmiPath[dStart..dEnd] : "";
                return $"{domain}\\{name}";
            }
            return name;
        }
        catch
        {
            return wmiPath;
        }
    }
}

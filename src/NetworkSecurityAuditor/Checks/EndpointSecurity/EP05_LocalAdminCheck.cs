namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP05 - Local admin group members, unquoted service paths, AlwaysInstallElevated,
///        cached logon count, Administrator Protection state.
/// </summary>
public sealed class EP05_LocalAdminCheck : ISecurityCheck
{
    public string Id => "EP05";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Local Administrators group members
            ct.ThrowIfCancellationRequested();
            EnumerateLocalAdmins(sb, evidence, ref hasIssue);

            // 2. Unquoted service paths
            ct.ThrowIfCancellationRequested();
            CheckUnquotedServicePaths(sb, evidence, ref hasIssue);

            // 3. AlwaysInstallElevated
            ct.ThrowIfCancellationRequested();
            CheckAlwaysInstallElevated(sb, evidence, ref hasIssue);

            // 4. Cached logon count
            ct.ThrowIfCancellationRequested();
            CheckCachedLogonCount(sb, evidence, ref hasIssue);

            // 5. Administrator Protection (Win11 24H2+)
            ct.ThrowIfCancellationRequested();
            CheckAdminProtection(sb, evidence);

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

    private static void EnumerateLocalAdmins(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("[Local Administrators Group]");
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT GroupComponent, PartComponent FROM Win32_GroupUser");

            var adminMembers = new List<string>();

            foreach (ManagementObject obj in searcher.Get())
            {
                string group = obj["GroupComponent"]?.ToString() ?? "";
                string member = obj["PartComponent"]?.ToString() ?? "";

                // Filter for Administrators group
                if (!group.Contains("\"Administrators\"", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Extract the account name from the WMI path
                string accountName = ExtractWmiName(member);
                adminMembers.Add(accountName);
                evidence.AppendLine($"  {accountName}");
            }

            sb.AppendLine($"Local Administrators group has {adminMembers.Count} member(s).");

            if (adminMembers.Count > 3)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {adminMembers.Count} members in Administrators group is excessive. Limit to essential accounts only.");
            }

            // Check for overly broad group memberships
            var broadGroups = new[] { "Domain Users", "Everyone", "Authenticated Users", "Users" };
            foreach (var broad in broadGroups)
            {
                if (adminMembers.Any(m => m.Contains(broad, StringComparison.OrdinalIgnoreCase)))
                {
                    hasIssue = true;
                    sb.AppendLine($"CRITICAL: '{broad}' is a member of local Administrators. This grants admin to all users in that group.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  Error querying group: {ex.Message}");
            sb.AppendLine("Could not enumerate local Administrators group via WMI.");
        }
    }

    private static void CheckUnquotedServicePaths(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[Unquoted Service Paths]");
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PathName, StartMode FROM Win32_Service WHERE StartMode <> 'Disabled'");

            int unquotedCount = 0;

            foreach (ManagementObject obj in searcher.Get())
            {
                string? path = obj["PathName"]?.ToString();
                string name = obj["Name"]?.ToString() ?? "";

                if (string.IsNullOrWhiteSpace(path)) continue;

                // Skip system32 paths (not exploitable without prior system access)
                if (path.Contains(@"\system32\", StringComparison.OrdinalIgnoreCase)) continue;
                if (path.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase)) continue;

                // Check: path has spaces, is NOT quoted, and has more than one path segment
                if (!path.StartsWith('"') && path.Contains(' '))
                {
                    // Verify there's actually a space before the .exe
                    string exePath = path.Split(new[] { ".exe", ".EXE" }, StringSplitOptions.None)[0];
                    if (exePath.Contains(' ') && exePath.Contains('\\'))
                    {
                        unquotedCount++;
                        evidence.AppendLine($"  {name}: {path}");
                    }
                }
            }

            if (unquotedCount > 0)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: {unquotedCount} service(s) have unquoted paths with spaces (privilege escalation vector).");
            }
            else
            {
                sb.AppendLine("PASS: No unquoted service paths detected.");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
        }
    }

    private static void CheckAlwaysInstallElevated(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[AlwaysInstallElevated]");

        int hklm = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0);
        int hkcu = RegistryHelper.GetValue<int>(
            @"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0);

        evidence.AppendLine($"  HKLM = {hklm}");
        evidence.AppendLine($"  HKCU = {hkcu}");

        if (hklm == 1 && hkcu == 1)
        {
            hasIssue = true;
            sb.AppendLine("CRITICAL: AlwaysInstallElevated is enabled in BOTH HKLM and HKCU. Any user can install MSI packages as SYSTEM.");
        }
        else if (hklm == 1 || hkcu == 1)
        {
            sb.AppendLine("WARNING: AlwaysInstallElevated is set in one hive (both required to exploit, but policy should be reviewed).");
        }
        else
        {
            sb.AppendLine("PASS: AlwaysInstallElevated is not enabled.");
        }
    }

    private static void CheckCachedLogonCount(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[Cached Logon Count]");

        string? cached = RegistryHelper.GetValue<string>(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", "10");

        evidence.AppendLine($"  CachedLogonsCount = {cached}");

        if (int.TryParse(cached, out int count))
        {
            if (count > 4)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: CachedLogonsCount = {count}. CIS recommends <= 4 to limit offline credential exposure.");
            }
            else
            {
                sb.AppendLine($"PASS: CachedLogonsCount = {count} (<= 4).");
            }
        }
    }

    private static void CheckAdminProtection(StringBuilder sb, StringBuilder evidence)
    {
        // Administrator Protection (Windows 11 24H2+) - splits admin token
        evidence.AppendLine("\n[Administrator Protection]");

        int adminProtection = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "TypeOfAdminApprovalMode", -1);

        evidence.AppendLine($"  TypeOfAdminApprovalMode = {adminProtection}");

        string desc = adminProtection switch
        {
            0 => "Disabled",
            1 => "Admin Approval Mode (classic UAC)",
            2 => "Administrator Protection (enhanced, Win11 24H2+)",
            _ => "Not configured"
        };

        sb.AppendLine($"Administrator Protection mode: {desc}.");
        if (adminProtection == 2)
            sb.AppendLine("INFO: Administrator Protection is the strongest UAC posture available.");
    }

    private static string ExtractWmiName(string wmiPath)
    {
        // WMI paths look like: \\COMPUTER\root\cimv2:Win32_UserAccount.Domain="X",Name="Y"
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

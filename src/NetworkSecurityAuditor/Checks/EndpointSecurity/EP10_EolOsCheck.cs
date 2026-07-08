namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// EP10 - End-of-life operating systems: local OS lifecycle check + AD computer OS distribution.
/// </summary>
public sealed class EP10_EolOsCheck : ISecurityCheck
{
    public string Id => "EP10";

    // EOL OS patterns (substring match against WMI Caption/Name).
    // Key = pattern, Value = (EOL date, friendly label).
    private static readonly (string Pattern, string Label, string EolDate)[] EolOsList =
    [
        ("Windows XP", "Windows XP", "2014-04-08"),
        ("Windows Vista", "Windows Vista", "2017-04-11"),
        ("Windows 7", "Windows 7", "2020-01-14"),
        ("Windows 8 ", "Windows 8", "2016-01-12"),
        ("Windows 8.1", "Windows 8.1", "2023-01-10"),
        ("Server 2003", "Windows Server 2003", "2015-07-14"),
        ("Server 2008 R2", "Windows Server 2008 R2", "2020-01-14"),
        ("Server 2008", "Windows Server 2008", "2020-01-14"),
        ("Server 2012 R2", "Windows Server 2012 R2", "2023-10-10"),
        ("Server 2012", "Windows Server 2012", "2023-10-10"),
    ];

    // Windows 10 reaches end of support 2025-10-14
    private static readonly DateTime Win10EolDate = new(2025, 10, 14);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Check local OS against lifecycle table
            ct.ThrowIfCancellationRequested();
            CheckLocalOs(env, sb, evidence, ref hasIssue);

            // 2. If domain-joined with AD access, query AD computers for OS distribution
            ct.ThrowIfCancellationRequested();
            if (env.IsDomainJoined && env.HasAD)
            {
                QueryAdComputerOsDistribution(sb, evidence, ref hasIssue, ct);
            }
            else
            {
                evidence.AppendLine("\n[AD OS Distribution] Skipped (not domain-joined or no AD access).");
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

    private static void CheckLocalOs(EnvironmentInfo env, StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("[Local OS Lifecycle]");
        evidence.AppendLine($"  Caption: {env.OSCaption}");
        evidence.AppendLine($"  Build: {env.OSBuild}");
        evidence.AppendLine($"  Version: {env.OSVersion}");

        string caption = env.OSCaption;

        // Check against known EOL list
        foreach (var (pattern, label, eolDate) in EolOsList)
        {
            if (caption.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: This system is running {label}, which reached end of life on {eolDate}.");
                sb.AppendLine("  No security updates are available. Immediate upgrade required.");
                evidence.AppendLine($"  MATCH: {label} (EOL {eolDate})");
                return;
            }
        }

        // Special handling for Windows 10 (approaching EOL)
        if (caption.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
        {
            int daysUntilEol = (int)(Win10EolDate - DateTime.Now).TotalDays;
            evidence.AppendLine($"  Windows 10 EOL: {Win10EolDate:yyyy-MM-dd} ({daysUntilEol} days remaining)");

            if (daysUntilEol <= 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: Windows 10 reached end of support on {Win10EolDate:yyyy-MM-dd}. Upgrade to Windows 11.");
            }
            else if (daysUntilEol <= 180)
            {
                sb.AppendLine($"WARNING: Windows 10 end of support is {Win10EolDate:yyyy-MM-dd} ({daysUntilEol} days). Plan migration to Windows 11.");
            }
            else
            {
                sb.AppendLine($"Windows 10 is currently supported. End of support: {Win10EolDate:yyyy-MM-dd} ({daysUntilEol} days remaining).");
            }
            return;
        }

        // Not EOL
        sb.AppendLine($"Local OS ({caption}) is not flagged as end-of-life.");
    }

    private static void QueryAdComputerOsDistribution(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[AD Computer OS Distribution]");

        try
        {
            // Attempt LDAP query when Active Directory access is available.
            QueryAdViaLdap(sb, evidence, ref hasIssue, ct);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error querying AD: {ex.Message}");
            sb.AppendLine("INFO: Could not query AD for OS distribution.");
        }
    }

    private static void QueryAdViaLdap(StringBuilder sb, StringBuilder evidence,
        ref bool hasIssue, CancellationToken ct)
    {
        try
        {
            // Use System.DirectoryServices to query computer objects
            using var entry = new System.DirectoryServices.DirectoryEntry("LDAP://RootDSE");
            string? defaultNamingContext = entry.Properties["defaultNamingContext"]?.Value?.ToString();
            if (string.IsNullOrEmpty(defaultNamingContext))
            {
                evidence.AppendLine("  Could not determine AD naming context.");
                return;
            }

            using var searchRoot = new System.DirectoryServices.DirectoryEntry($"LDAP://{defaultNamingContext}");
            using var adSearcher = new System.DirectoryServices.DirectorySearcher(searchRoot)
            {
                Filter = "(objectClass=computer)",
                PageSize = 1000,
            };
            adSearcher.PropertiesToLoad.AddRange(["operatingSystem", "operatingSystemVersion", "name"]);

            var osCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int totalComputers = 0;
            int eolCount = 0;
            int win10Count = 0;
            int win11Count = 0;

            using var results = adSearcher.FindAll();
            foreach (System.DirectoryServices.SearchResult result in results)
            {
                ct.ThrowIfCancellationRequested();
                totalComputers++;

                string os = result.Properties["operatingSystem"]?.Count > 0
                    ? result.Properties["operatingSystem"][0]?.ToString() ?? "Unknown"
                    : "Unknown";

                osCounts.TryGetValue(os, out int count);
                osCounts[os] = count + 1;

                // Track EOL
                foreach (var (pattern, _, _) in EolOsList)
                {
                    if (os.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        eolCount++;
                        break;
                    }
                }

                if (os.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
                    win10Count++;
                if (os.Contains("Windows 11", StringComparison.OrdinalIgnoreCase))
                    win11Count++;
            }

            evidence.AppendLine($"  Total AD computers: {totalComputers}");
            foreach (var (os, count) in osCounts.OrderByDescending(kv => kv.Value))
            {
                evidence.AppendLine($"    {os}: {count}");
            }

            sb.AppendLine($"AD OS distribution: {totalComputers} computers found.");

            if (eolCount > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {eolCount} computer(s) in AD are running end-of-life operating systems.");
            }

            if (win10Count > 0 && win11Count > 0)
            {
                int totalWorkstations = win10Count + win11Count;
                int migrationPct = (int)((double)win11Count / totalWorkstations * 100);
                sb.AppendLine($"Windows 10 to 11 migration: {migrationPct}% ({win11Count}/{totalWorkstations} workstations on Win11).");
            }
            else if (win10Count > 0 && win11Count == 0)
            {
                sb.AppendLine($"WARNING: {win10Count} Windows 10 workstation(s) found, 0 on Windows 11. Migration not started.");
            }
        }
        catch (System.Runtime.InteropServices.COMException ex)
        {
            evidence.AppendLine($"  LDAP query error: {ex.Message}");
            sb.AppendLine("INFO: Could not query AD computer objects (may require domain connectivity or permissions).");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  AD query error: {ex.Message}");
            sb.AppendLine("INFO: AD OS distribution query failed.");
        }
    }
}

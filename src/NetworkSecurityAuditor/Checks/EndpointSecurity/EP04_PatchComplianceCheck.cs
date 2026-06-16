namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// EP04 - Patch compliance: hotfix recency, OS build currency, patch count.
/// </summary>
public sealed class EP04_PatchComplianceCheck : ISecurityCheck
{
    public string Id => "EP04";

    private const int StalePatchDays = 30;

    // Known current Windows 10/11/Server builds as of 2025-Q2.
    // Key = major build number, Value = (friendly name, is current).
    private static readonly Dictionary<int, string> KnownCurrentBuilds = new()
    {
        { 26100, "Windows 11 24H2 / Server 2025" },
        { 22631, "Windows 11 23H2" },
        { 22621, "Windows 11 22H2" },
        { 19045, "Windows 10 22H2" },
        { 20348, "Windows Server 2022" },
        { 17763, "Windows Server 2019 / Windows 10 1809 LTSC" },
        { 14393, "Windows Server 2016 / Windows 10 1607 LTSC" },
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // -- Query installed hotfixes via WMI --
            ct.ThrowIfCancellationRequested();
            var hotfixes = QueryHotfixes(evidence, ct);

            evidence.AppendLine($"\n[Summary] Total hotfixes returned: {hotfixes.Count}");

            if (hotfixes.Count == 0)
            {
                hasIssue = true;
                sb.AppendLine("WARNING: No hotfix records returned from WMI (Win32_QuickFixEngineering).");
                sb.AppendLine("  This may indicate WMI issues or that updates are managed by a non-standard mechanism.");
            }
            else
            {
                // Find most recent hotfix
                var mostRecent = hotfixes
                    .Where(h => h.InstalledOn != DateTime.MinValue)
                    .OrderByDescending(h => h.InstalledOn)
                    .FirstOrDefault();

                if (mostRecent != default)
                {
                    int daysSinceLast = (int)(DateTime.Now - mostRecent.InstalledOn).TotalDays;
                    evidence.AppendLine($"  Most recent hotfix: {mostRecent.HotFixId} installed {mostRecent.InstalledOn:yyyy-MM-dd} ({daysSinceLast} days ago)");

                    sb.AppendLine($"Hotfix count: {hotfixes.Count}. Most recent: {mostRecent.HotFixId} ({mostRecent.InstalledOn:yyyy-MM-dd}, {daysSinceLast}d ago).");

                    if (daysSinceLast > StalePatchDays)
                    {
                        hasIssue = true;
                        sb.AppendLine($"FAIL: Last hotfix is {daysSinceLast} days old (threshold: {StalePatchDays} days). System may be missing security updates.");
                    }
                }
                else
                {
                    sb.AppendLine($"Hotfix count: {hotfixes.Count}, but no install dates could be parsed.");
                    sb.AppendLine("WARNING: Cannot determine patch recency without install dates.");
                }
            }

            // -- OS build currency --
            ct.ThrowIfCancellationRequested();
            CheckBuildCurrency(env, sb, evidence, ref hasIssue);

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

    private static List<HotfixInfo> QueryHotfixes(StringBuilder evidence, CancellationToken ct)
    {
        var results = new List<HotfixInfo>();
        evidence.AppendLine("[Installed Hotfixes (Win32_QuickFixEngineering)]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT HotFixID, InstalledOn, Description, InstalledBy FROM Win32_QuickFixEngineering");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();

                string id = obj["HotFixID"]?.ToString() ?? "Unknown";
                string desc = obj["Description"]?.ToString() ?? "";
                string installedBy = obj["InstalledBy"]?.ToString() ?? "";
                DateTime installedOn = DateTime.MinValue;

                try
                {
                    var raw = obj["InstalledOn"];
                    if (raw is string dateStr && DateTime.TryParse(dateStr, out var parsed))
                        installedOn = parsed;
                    else if (raw is DateTime dt)
                        installedOn = dt;
                }
                catch
                {
                    // InstalledOn can be in various formats
                }

                results.Add(new HotfixInfo(id, installedOn, desc));
                evidence.AppendLine($"  {id}: {(installedOn == DateTime.MinValue ? "date unknown" : installedOn.ToString("yyyy-MM-dd"))}, {desc}");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        return results;
    }

    private static void CheckBuildCurrency(EnvironmentInfo env, StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine($"\n[OS Build Currency]");
        evidence.AppendLine($"  OS Build: {env.OSBuild}");
        evidence.AppendLine($"  OS Version: {env.OSVersion}");
        evidence.AppendLine($"  OS Caption: {env.OSCaption}");

        if (env.OSBuild <= 0)
        {
            sb.AppendLine("INFO: OS build number not available for currency check.");
            return;
        }

        if (KnownCurrentBuilds.TryGetValue(env.OSBuild, out string? buildName))
        {
            sb.AppendLine($"OS build {env.OSBuild} ({buildName}) is a recognized current release.");
        }
        else
        {
            // Check if it's an older/unknown build
            bool isOlder = env.OSBuild < 14393; // Anything older than Server 2016 / Win10 1607
            if (isOlder)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: OS build {env.OSBuild} is not a recognized current build. This system may be running an end-of-life or unsupported OS version.");
            }
            else
            {
                sb.AppendLine($"INFO: OS build {env.OSBuild} is not in the known-current list. Verify it is receiving security updates.");
            }
        }
    }

    private readonly record struct HotfixInfo(string HotFixId, DateTime InstalledOn, string Description);
}

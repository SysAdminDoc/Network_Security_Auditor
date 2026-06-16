namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// BR01 - Backup Solution: Check for backup services (Veeam, Acronis, Windows Server Backup,
/// Datto, Commvault). Check Volume Shadow Copy service.
/// </summary>
public sealed class BR01_BackupSolutionCheck : ISecurityCheck
{
    public string Id => "BR01";

    private static readonly Dictionary<string, string> BackupServices = new(StringComparer.OrdinalIgnoreCase)
    {
        { "VeeamBackupSvc", "Veeam Backup Service" },
        { "VeeamEndpointBackupSvc", "Veeam Agent" },
        { "AcronisAgent", "Acronis Backup Agent" },
        { "MMS", "Acronis Managed Machine Service" },
        { "wbengine", "Windows Server Backup (Block Level)" },
        { "DattoBackupAgent", "Datto Backup Agent" },
        { "GxCIMgr", "Commvault Client" },
        { "GxClMgrS", "Commvault Communications" },
        { "BackupExecAgentBrowser", "Veritas Backup Exec Agent" },
        { "ArcserveUDP", "Arcserve UDP" },
        { "CarboniteService", "Carbonite" },
        { "CrashPlanService", "CrashPlan" },
        { "StorageCraftImageManager", "StorageCraft" },
    };

    private static readonly Dictionary<string, string> BackupRegistryKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        { @"HKLM\SOFTWARE\Veeam", "Veeam" },
        { @"HKLM\SOFTWARE\Acronis", "Acronis" },
        { @"HKLM\SOFTWARE\Datto", "Datto" },
        { @"HKLM\SOFTWARE\CommVault Systems", "Commvault" },
        { @"HKLM\SOFTWARE\Veritas\Backup Exec", "Veritas Backup Exec" },
        { @"HKLM\SOFTWARE\Arcserve", "Arcserve" },
        { @"HKLM\SOFTWARE\StorageCraft", "StorageCraft" },
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool backupFound = false;
            var detectedProducts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Check for backup services via WMI
            ct.ThrowIfCancellationRequested();
            CheckBackupServices(sb, evidence, ref backupFound, detectedProducts, ct);

            // 2. Check Volume Shadow Copy service
            ct.ThrowIfCancellationRequested();
            CheckVssService(sb, evidence, ct);

            // 3. Check registry for backup software
            ct.ThrowIfCancellationRequested();
            CheckBackupRegistry(sb, evidence, ref backupFound, detectedProducts);

            // 4. Check Windows Backup status
            ct.ThrowIfCancellationRequested();
            CheckWindowsBackup(sb, evidence, ref backupFound);

            // Summary
            if (backupFound)
            {
                sb.Insert(0, $"Backup solution(s) detected: {string.Join(", ", detectedProducts)}.\n");
            }
            else
            {
                sb.Insert(0, "No backup solution detected on this system.\n");
                sb.AppendLine("CRITICAL: No backup software or service found. Implement a backup solution " +
                    "following the 3-2-1 rule (3 copies, 2 media types, 1 offsite).");
            }

            var status = backupFound ? CheckStatus.Pass : CheckStatus.Fail;

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

    private static void CheckBackupServices(StringBuilder sb, StringBuilder evidence,
        ref bool backupFound, HashSet<string> detectedProducts, CancellationToken ct)
    {
        evidence.AppendLine("[Backup Service Check]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, StartMode FROM Win32_Service");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string name = obj["Name"]?.ToString() ?? "";
                string displayName = obj["DisplayName"]?.ToString() ?? "";
                string state = obj["State"]?.ToString() ?? "";
                string startMode = obj["StartMode"]?.ToString() ?? "";

                if (BackupServices.TryGetValue(name, out string? product))
                {
                    backupFound = true;
                    detectedProducts.Add(product);
                    evidence.AppendLine($"  FOUND: {displayName} ({name}) - {state} ({startMode})");
                    sb.AppendLine($"Backup service: {product} - {state}");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckVssService(StringBuilder sb, StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[Volume Shadow Copy Service]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'VSS'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                string startMode = obj["StartMode"]?.ToString() ?? "Unknown";

                evidence.AppendLine($"  VSS: State={state}, StartMode={startMode}");

                if (startMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    sb.AppendLine("WARNING: Volume Shadow Copy service is disabled. " +
                        "VSS is required for most Windows backup solutions.");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }

        // Check for shadow copies
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ID, VolumeName, InstallDate FROM Win32_ShadowCopy");

            int shadowCount = 0;
            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                shadowCount++;
                if (shadowCount <= 5)
                    evidence.AppendLine($"  Shadow copy: {obj["VolumeName"]} ({obj["InstallDate"]})");
            }

            evidence.AppendLine($"  Total shadow copies: {shadowCount}");
            if (shadowCount > 0)
                sb.AppendLine($"Volume Shadow Copies: {shadowCount} snapshot(s) found.");
        }
        catch (ManagementException)
        {
            evidence.AppendLine("  Could not enumerate shadow copies (may require elevation).");
        }
    }

    private static void CheckBackupRegistry(StringBuilder sb, StringBuilder evidence,
        ref bool backupFound, HashSet<string> detectedProducts)
    {
        evidence.AppendLine("\n[Backup Software Registry]");

        foreach (var (path, label) in BackupRegistryKeys)
        {
            if (RegistryHelper.KeyExists(path))
            {
                if (detectedProducts.Add(label))
                {
                    backupFound = true;
                    evidence.AppendLine($"  FOUND: {label} ({path})");
                    sb.AppendLine($"Backup software detected: {label}");
                }
            }
        }
    }

    private static void CheckWindowsBackup(StringBuilder sb, StringBuilder evidence, ref bool backupFound)
    {
        evidence.AppendLine("\n[Windows Backup Configuration]");

        // Check for Windows Server Backup feature
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows Server Backup"))
        {
            backupFound = true;
            evidence.AppendLine("  Windows Server Backup feature detected.");
            sb.AppendLine("Windows Server Backup feature is installed.");
        }

        // Check for File History
        int fileHistory = RegistryHelper.GetValue<int>(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\FileHistory",
            "ProtectionEnabled", -1);

        if (fileHistory == 1)
        {
            backupFound = true;
            evidence.AppendLine("  File History: Enabled");
            sb.AppendLine("Windows File History is enabled.");
        }
        else
        {
            evidence.AppendLine("  File History: Not enabled or not configured.");
        }
    }
}

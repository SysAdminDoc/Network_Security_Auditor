namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// BR02 - Offsite/Immutable Backups: Heuristic check for cloud backup indicators
/// and offsite replication services. Interview required for full assessment.
/// </summary>
public sealed class BR02_OffsiteBackupCheck : ISecurityCheck
{
    public string Id => "BR02";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool cloudBackupFound = false;

            // 1. Check for cloud backup services
            ct.ThrowIfCancellationRequested();
            CheckCloudBackupServices(sb, evidence, ref cloudBackupFound, ct);

            // 2. Check for cloud sync/backup software
            ct.ThrowIfCancellationRequested();
            CheckCloudBackupSoftware(sb, evidence, ref cloudBackupFound);

            // 3. Check for Azure Backup agent
            ct.ThrowIfCancellationRequested();
            CheckAzureBackup(sb, evidence, ref cloudBackupFound);

            // Summary and checklist
            if (cloudBackupFound)
            {
                sb.Insert(0, "Cloud/offsite backup indicators detected.\n");
            }
            else
            {
                sb.Insert(0, "No cloud/offsite backup indicators detected on this host.\n");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Offsite/Immutable Backup Review:");
            sb.AppendLine("  [ ] Backups are replicated to an offsite location");
            sb.AppendLine("  [ ] At least one backup copy is immutable (write-once, cannot be deleted)");
            sb.AppendLine("  [ ] Offsite backup is in a geographically separate location");
            sb.AppendLine("  [ ] Offsite backup is tested for restorability");
            sb.AppendLine("  [ ] Backup retention policy meets business requirements");
            sb.AppendLine("  [ ] Air-gapped backup copy exists for ransomware resilience");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview-based assessment needed " +
                "to confirm offsite backup strategy and immutability settings.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void CheckCloudBackupServices(StringBuilder sb, StringBuilder evidence,
        ref bool cloudBackupFound, CancellationToken ct)
    {
        evidence.AppendLine("[Cloud Backup Services]");

        string[] cloudServiceNames =
        [
            "CarboniteService", "CrashPlanService", "BackblazeService",
            "MozyBackup", "IDriveService", "SpiderOakONE",
            "CloudBerryBackup", "MSP360"
        ];

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State FROM Win32_Service");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string name = obj["Name"]?.ToString() ?? "";
                string displayName = obj["DisplayName"]?.ToString() ?? "";

                foreach (string svc in cloudServiceNames)
                {
                    if (name.Contains(svc, StringComparison.OrdinalIgnoreCase) ||
                        displayName.Contains(svc, StringComparison.OrdinalIgnoreCase))
                    {
                        cloudBackupFound = true;
                        string state = obj["State"]?.ToString() ?? "Unknown";
                        evidence.AppendLine($"  FOUND: {displayName} ({name}) - {state}");
                        sb.AppendLine($"Cloud backup service: {displayName} ({state})");
                        break;
                    }
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckCloudBackupSoftware(StringBuilder sb, StringBuilder evidence,
        ref bool cloudBackupFound)
    {
        evidence.AppendLine("\n[Cloud Backup Software Registry]");

        var cloudSoftware = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Carbonite", "Carbonite" },
            { @"HKLM\SOFTWARE\CrashPlan", "CrashPlan" },
            { @"HKLM\SOFTWARE\Backblaze", "Backblaze" },
            { @"HKLM\SOFTWARE\IDrive", "IDrive" },
            { @"HKLM\SOFTWARE\MSP360", "MSP360 (CloudBerry)" },
            { @"HKLM\SOFTWARE\Druva", "Druva inSync" },
        };

        foreach (var (path, label) in cloudSoftware)
        {
            if (RegistryHelper.KeyExists(path))
            {
                cloudBackupFound = true;
                evidence.AppendLine($"  FOUND: {label} ({path})");
                sb.AppendLine($"Cloud backup software detected: {label}");
            }
        }
    }

    private static void CheckAzureBackup(StringBuilder sb, StringBuilder evidence,
        ref bool cloudBackupFound)
    {
        evidence.AppendLine("\n[Azure/AWS Backup Agent]");

        // Azure Backup (MARS) agent
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows Azure Backup"))
        {
            cloudBackupFound = true;
            evidence.AppendLine("  FOUND: Azure Backup (MARS) agent");
            sb.AppendLine("Azure Backup agent (MARS) detected.");
        }

        // AWS Backup
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Amazon\AWSBackup"))
        {
            cloudBackupFound = true;
            evidence.AppendLine("  FOUND: AWS Backup agent");
            sb.AppendLine("AWS Backup agent detected.");
        }

        if (!cloudBackupFound)
            evidence.AppendLine("  No cloud backup agent registry keys found.");
    }
}

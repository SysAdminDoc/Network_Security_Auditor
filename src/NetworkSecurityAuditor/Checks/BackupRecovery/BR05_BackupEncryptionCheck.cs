namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// BR05 - Backup Encryption: External-required. Check backup service encryption settings
/// where detectable.
/// </summary>
public sealed class BR05_BackupEncryptionCheck : ISecurityCheck
{
    public string Id => "BR05";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool encryptionDetected = false;

            // 1. Check for BitLocker on backup-relevant volumes
            ct.ThrowIfCancellationRequested();
            CheckBitLockerVolumes(sb, evidence, ref encryptionDetected, ct);

            // 2. Check for backup software encryption indicators
            ct.ThrowIfCancellationRequested();
            CheckBackupSoftwareEncryption(sb, evidence, ref encryptionDetected);

            // 3. Check for EFS usage on common backup paths
            ct.ThrowIfCancellationRequested();
            CheckEfsIndicators(evidence);

            // Summary and checklist
            if (encryptionDetected)
            {
                sb.Insert(0, "Some encryption indicators detected for backup data.\n");
            }
            else
            {
                sb.Insert(0, "No backup encryption indicators detected.\n");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Backup Encryption Review:");
            sb.AppendLine("  [ ] Backup data is encrypted at rest (AES-256 or equivalent)");
            sb.AppendLine("  [ ] Backup data is encrypted in transit (TLS 1.2+)");
            sb.AppendLine("  [ ] Encryption keys are stored separately from backup data");
            sb.AppendLine("  [ ] Key management procedures are documented");
            sb.AppendLine("  [ ] Encryption key recovery process is tested");
            sb.AppendLine("  [ ] Cloud backup encryption keys are customer-managed (not provider-managed)");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Check backup software configuration " +
                "for encryption settings. This cannot be fully automated.");

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

    private static void CheckBitLockerVolumes(StringBuilder sb, StringBuilder evidence,
        ref bool encryptionDetected, CancellationToken ct)
    {
        evidence.AppendLine("[BitLocker Volume Encryption]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string drive = obj["DriveLetter"]?.ToString() ?? "Unknown";
                int protection = Convert.ToInt32(obj["ProtectionStatus"] ?? 0);
                int conversion = Convert.ToInt32(obj["ConversionStatus"] ?? 0);

                string protStatus = protection switch
                {
                    0 => "Off",
                    1 => "On",
                    2 => "Unknown",
                    _ => protection.ToString()
                };

                evidence.AppendLine($"  {drive}: Protection={protStatus}, Conversion={conversion}");

                if (protection == 1)
                {
                    encryptionDetected = true;
                    sb.AppendLine($"BitLocker encryption active on {drive}.");
                }
            }
        }
        catch (ManagementException)
        {
            evidence.AppendLine("  BitLocker WMI not accessible (may require elevation or BitLocker not available).");
        }
    }

    private static void CheckBackupSoftwareEncryption(StringBuilder sb, StringBuilder evidence,
        ref bool encryptionDetected)
    {
        evidence.AppendLine("\n[Backup Software Encryption Indicators]");

        // Veeam encryption setting
        int veeamEncrypt = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Veeam\Veeam Backup and Replication",
            "EnableEncryption", -1);

        if (veeamEncrypt >= 0)
        {
            evidence.AppendLine($"  Veeam EnableEncryption: {veeamEncrypt}");
            if (veeamEncrypt == 1)
            {
                encryptionDetected = true;
                sb.AppendLine("Veeam backup encryption is enabled.");
            }
        }

        // Windows Server Backup encryption
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows Server Backup\Encryption"))
        {
            encryptionDetected = true;
            evidence.AppendLine("  Windows Server Backup encryption key found.");
        }
    }

    private static void CheckEfsIndicators(StringBuilder evidence)
    {
        evidence.AppendLine("\n[EFS (Encrypting File System)]");

        // Check if EFS is available
        int efsEnabled = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\EFS",
            "EfsConfiguration", -1);

        evidence.AppendLine($"  EFS policy: {(efsEnabled == -1 ? "Not configured" : efsEnabled.ToString())}");
    }
}

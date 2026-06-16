namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP02 - BitLocker encryption, TPM, and Secure Boot status.
/// </summary>
public sealed class EP02_BitLockerCheck : ISecurityCheck
{
    public string Id => "EP02";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            bool anyDriveEncrypted = false;

            // -- BitLocker via WMI --
            ct.ThrowIfCancellationRequested();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    "SELECT DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod FROM Win32_EncryptableVolume");

                evidence.AppendLine("[BitLocker Volume Status]");

                foreach (ManagementObject obj in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();

                    string drive = obj["DriveLetter"]?.ToString() ?? "?:";
                    int protectionStatus = Convert.ToInt32(obj["ProtectionStatus"] ?? 0);
                    int conversionStatus = Convert.ToInt32(obj["ConversionStatus"] ?? 0);
                    int encMethod = Convert.ToInt32(obj["EncryptionMethod"] ?? 0);

                    string protLabel = protectionStatus switch
                    {
                        0 => "OFF",
                        1 => "ON",
                        2 => "UNKNOWN",
                        _ => $"Unknown({protectionStatus})"
                    };

                    string convLabel = conversionStatus switch
                    {
                        0 => "FullyDecrypted",
                        1 => "FullyEncrypted",
                        2 => "EncryptionInProgress",
                        3 => "DecryptionInProgress",
                        4 => "EncryptionPaused",
                        5 => "DecryptionPaused",
                        _ => $"Unknown({conversionStatus})"
                    };

                    string methodLabel = encMethod switch
                    {
                        0 => "None",
                        1 => "AES-128-Diffuser",
                        2 => "AES-256-Diffuser",
                        3 => "AES-128",
                        4 => "AES-256",
                        6 => "XTS-AES-128",
                        7 => "XTS-AES-256",
                        _ => $"Unknown({encMethod})"
                    };

                    evidence.AppendLine($"  {drive}: Protection={protLabel}, Conversion={convLabel}, Method={methodLabel}");

                    if (protectionStatus == 1 && conversionStatus == 1)
                    {
                        anyDriveEncrypted = true;
                    }
                    else
                    {
                        hasIssue = true;
                        sb.AppendLine($"WARNING: Drive {drive} is not fully encrypted (Protection={protLabel}, Status={convLabel}).");
                    }
                }
            }
            catch (ManagementException ex)
            {
                hasIssue = true;
                sb.AppendLine($"BitLocker WMI query failed: {ex.Message}");
                evidence.AppendLine($"[BitLocker WMI Error] {ex.Message}");
                if (!env.IsAdmin)
                    sb.AppendLine("  (BitLocker WMI requires administrator privileges.)");
            }

            // -- TPM Status --
            ct.ThrowIfCancellationRequested();
            CheckTPM(sb, evidence, ref hasIssue);

            // -- Secure Boot --
            ct.ThrowIfCancellationRequested();
            CheckSecureBoot(sb, evidence, ref hasIssue);

            if (!hasIssue && anyDriveEncrypted)
                sb.Insert(0, "All volumes are BitLocker-encrypted, TPM and Secure Boot verified.\n");

            var status = hasIssue
                ? (anyDriveEncrypted ? CheckStatus.Partial : CheckStatus.Fail)
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

    private static void CheckTPM(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftTpm",
                "SELECT IsActivated_InitialValue, IsEnabled_InitialValue, IsOwned_InitialValue, SpecVersion FROM Win32_Tpm");

            evidence.AppendLine("\n[TPM Status]");
            foreach (ManagementObject obj in searcher.Get())
            {
                bool activated = obj["IsActivated_InitialValue"] is true;
                bool enabled = obj["IsEnabled_InitialValue"] is true;
                bool owned = obj["IsOwned_InitialValue"] is true;
                string specVersion = obj["SpecVersion"]?.ToString() ?? "Unknown";

                evidence.AppendLine($"  Activated={activated}, Enabled={enabled}, Owned={owned}, SpecVersion={specVersion}");

                if (!activated || !enabled)
                {
                    hasIssue = true;
                    sb.AppendLine("WARNING: TPM is not fully activated/enabled.");
                }

                if (specVersion.StartsWith("1.2"))
                {
                    sb.AppendLine("INFO: TPM 1.2 detected. TPM 2.0 is recommended for modern security features.");
                }
            }
        }
        catch (ManagementException)
        {
            evidence.AppendLine("\n[TPM Status] Not accessible via WMI.");
            sb.AppendLine("INFO: TPM status could not be queried (may require admin or UEFI).");
        }
    }

    private static void CheckSecureBoot(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        // Secure Boot state from registry
        int? secureBoot = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", -1);

        evidence.AppendLine($"\n[Secure Boot] Registry value = {secureBoot}");

        if (secureBoot == 1)
        {
            sb.AppendLine("Secure Boot: Enabled.");
        }
        else if (secureBoot == 0)
        {
            hasIssue = true;
            sb.AppendLine("WARNING: Secure Boot is DISABLED. Rootkit protection is reduced.");
        }
        else
        {
            sb.AppendLine("INFO: Secure Boot status could not be determined (Legacy BIOS or registry inaccessible).");
        }
    }
}

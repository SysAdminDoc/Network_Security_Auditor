namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP08 - Credential Guard, LSA protection, Secure Boot, and UEFI lock.
/// </summary>
public sealed class EP08_CredentialGuardCheck : ISecurityCheck
{
    public string Id => "EP08";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. Credential Guard via WMI (Win32_DeviceGuard)
            ct.ThrowIfCancellationRequested();
            CheckCredentialGuard(sb, evidence, ref failCount, ref totalChecks);

            // 2. LSA Protection (RunAsPPL)
            ct.ThrowIfCancellationRequested();
            CheckLsaProtection(sb, evidence, ref failCount, ref totalChecks);

            // 3. Secure Boot state
            ct.ThrowIfCancellationRequested();
            CheckSecureBoot(sb, evidence, ref failCount, ref totalChecks);

            // 4. UEFI lock
            ct.ThrowIfCancellationRequested();
            CheckUefiLock(sb, evidence, ref failCount, ref totalChecks);

            if (env.IsServer2025OrLater)
            {
                evidence.AppendLine("\n[Server 2025+ Defaults]");
                evidence.AppendLine("  Credential Guard: enabled by default on new deployments");
                evidence.AppendLine("  VBS: enabled by default with UEFI lock");
            }

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount < totalChecks ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"Credential protection: {totalChecks - failCount}/{totalChecks} controls active.\n");

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

    private static void CheckCredentialGuard(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("[Credential Guard via Win32_DeviceGuard]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\DeviceGuard",
                "SELECT SecurityServicesRunning, SecurityServicesConfigured, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard");

            bool found = false;
            foreach (ManagementObject obj in searcher.Get())
            {
                found = true;

                int vbsStatus = Convert.ToInt32(obj["VirtualizationBasedSecurityStatus"] ?? 0);
                string vbsLabel = vbsStatus switch
                {
                    0 => "Not enabled",
                    1 => "Enabled but not running",
                    2 => "Enabled and running",
                    _ => $"Unknown({vbsStatus})"
                };
                evidence.AppendLine($"  VBS Status: {vbsLabel}");

                // SecurityServicesRunning is an array of integers
                // 1 = Credential Guard, 2 = HVCI, 3 = System Guard Secure Launch
                var running = obj["SecurityServicesRunning"] as int[] ?? [];
                var configured = obj["SecurityServicesConfigured"] as int[] ?? [];

                string runningStr = running.Length > 0 ? string.Join(", ", running.Select(ServiceLabel)) : "None";
                string configStr = configured.Length > 0 ? string.Join(", ", configured.Select(ServiceLabel)) : "None";

                evidence.AppendLine($"  Services Running: {runningStr}");
                evidence.AppendLine($"  Services Configured: {configStr}");

                bool credGuardRunning = running.Contains(1);
                if (credGuardRunning)
                {
                    sb.AppendLine("Credential Guard: Running (VBS-backed credential isolation active).");
                }
                else if (configured.Contains(1))
                {
                    failCount++;
                    sb.AppendLine("WARNING: Credential Guard is configured but not running. VBS may not be active.");
                }
                else
                {
                    failCount++;
                    sb.AppendLine("FAIL: Credential Guard is not configured or running. LSASS credentials are not isolated.");
                }
            }

            if (!found)
            {
                failCount++;
                evidence.AppendLine("  Win32_DeviceGuard class not available.");
                sb.AppendLine("FAIL: Device Guard WMI not available. Credential Guard status unknown (likely not supported/enabled).");
            }
        }
        catch (ManagementException ex)
        {
            failCount++;
            evidence.AppendLine($"  WMI error: {ex.Message}");
            sb.AppendLine("INFO: Could not query Device Guard WMI. Credential Guard status unknown.");
        }
    }

    private static void CheckLsaProtection(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[LSA Protection (RunAsPPL)]");

        int runAsPPL = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", -1);

        evidence.AppendLine($"  RunAsPPL = {runAsPPL}");

        if (runAsPPL == 1 || runAsPPL == 2)
        {
            sb.AppendLine($"LSA Protection: Enabled (RunAsPPL={runAsPPL}). LSASS runs as Protected Process Light.");
        }
        else
        {
            failCount++;
            sb.AppendLine("FAIL: LSA Protection (RunAsPPL) is not enabled. LSASS is vulnerable to credential dumping tools (e.g., Mimikatz).");
        }

        // Also check the newer RunAsPPL setting under LSA\OSConfig (Windows 11+)
        int runAsPPLBoot = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig", "RunAsPPL", -1);
        if (runAsPPLBoot != -1)
        {
            evidence.AppendLine($"  OSConfig RunAsPPL = {runAsPPLBoot}");
        }
    }

    private static void CheckSecureBoot(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[Secure Boot]");

        int secureBoot = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", -1);

        evidence.AppendLine($"  UEFISecureBootEnabled = {secureBoot}");

        if (secureBoot == 1)
        {
            sb.AppendLine("Secure Boot: Enabled.");
        }
        else if (secureBoot == 0)
        {
            failCount++;
            sb.AppendLine("FAIL: Secure Boot is DISABLED. Boot-level rootkit protection is reduced.");
        }
        else
        {
            failCount++;
            sb.AppendLine("WARNING: Secure Boot status could not be determined (Legacy BIOS or registry inaccessible).");
        }
    }

    private static void CheckUefiLock(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[UEFI Lock]");

        // Device Guard UEFI lock prevents local admin from disabling VBS
        int uefiLock = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity", -1);
        int lockSetting = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "LsaCfgFlags", -1);

        evidence.AppendLine($"  EnableVirtualizationBasedSecurity (GPO) = {uefiLock}");
        evidence.AppendLine($"  LsaCfgFlags (GPO) = {lockSetting}");

        // LsaCfgFlags: 0 = Disabled, 1 = Enabled with UEFI lock, 2 = Enabled without lock
        if (lockSetting == 1)
        {
            sb.AppendLine("UEFI Lock: Credential Guard is UEFI-locked (cannot be disabled remotely).");
        }
        else if (lockSetting == 2)
        {
            sb.AppendLine("INFO: Credential Guard enabled without UEFI lock. A local admin can disable it.");
        }
        else if (uefiLock == 1)
        {
            sb.AppendLine("VBS enabled via policy but UEFI lock status not explicit.");
        }
        else
        {
            failCount++;
            sb.AppendLine("WARNING: VBS/Credential Guard UEFI lock is not configured via Group Policy.");
        }
    }

    private static string ServiceLabel(int id) => id switch
    {
        1 => "Credential Guard",
        2 => "HVCI (Hypervisor-enforced Code Integrity)",
        3 => "System Guard Secure Launch",
        4 => "SMM Firmware Measurement",
        _ => $"Unknown({id})"
    };
}

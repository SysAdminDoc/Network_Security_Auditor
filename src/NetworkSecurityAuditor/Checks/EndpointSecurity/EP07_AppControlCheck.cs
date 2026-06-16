namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP07 - Application control: AppLocker, WDAC/Code Integrity, Office macros,
/// Smart App Control, Windows Recall.
/// </summary>
public sealed class EP07_AppControlCheck : ISecurityCheck
{
    public string Id => "EP07";

    // AppLocker rule collection subkeys under SrpV2
    private static readonly string[] AppLockerCollections =
        ["Appx", "Dll", "Exe", "Msi", "Script"];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. AppLocker policy
            ct.ThrowIfCancellationRequested();
            CheckAppLocker(sb, evidence, ref failCount, ref totalChecks);

            // 2. WDAC / Code Integrity via Win32_DeviceGuard
            ct.ThrowIfCancellationRequested();
            CheckCodeIntegrity(sb, evidence, ref failCount, ref totalChecks);

            // 3. Office macro restrictions
            ct.ThrowIfCancellationRequested();
            CheckOfficeMacros(sb, evidence, ref failCount, ref totalChecks);

            // 4. Smart App Control
            ct.ThrowIfCancellationRequested();
            CheckSmartAppControl(sb, evidence, ref failCount, ref totalChecks);

            // 5. Windows Recall
            ct.ThrowIfCancellationRequested();
            CheckWindowsRecall(sb, evidence, ref failCount, ref totalChecks);

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount <= totalChecks / 2 ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"Application control: {totalChecks - failCount}/{totalChecks} checks passed.\n");

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

    private static void CheckAppLocker(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("[AppLocker Policy]");

        const string srpV2Key = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2";
        bool anyRules = false;

        foreach (string collection in AppLockerCollections)
        {
            string collectionPath = $@"{srpV2Key}\{collection}";
            var subkeys = RegistryHelper.GetSubKeyNames(collectionPath);

            if (subkeys.Length > 0)
            {
                anyRules = true;
                evidence.AppendLine($"  {collection}: {subkeys.Length} rule(s)");
            }
            else
            {
                evidence.AppendLine($"  {collection}: no rules");
            }
        }

        if (anyRules)
        {
            sb.AppendLine("AppLocker: Policy rules detected (at least one collection has rules configured).");
        }
        else
        {
            failCount++;
            sb.AppendLine("FAIL: No AppLocker rules configured. Application whitelisting is not enforced.");
        }
    }

    private static void CheckCodeIntegrity(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[WDAC / Code Integrity]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\DeviceGuard",
                "SELECT CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard");

            bool found = false;
            foreach (ManagementObject obj in searcher.Get())
            {
                found = true;
                int kernelCi = Convert.ToInt32(obj["CodeIntegrityPolicyEnforcementStatus"] ?? 0);
                int userCi = Convert.ToInt32(obj["UsermodeCodeIntegrityPolicyEnforcementStatus"] ?? 0);

                string kernelLabel = kernelCi switch
                {
                    0 => "Off",
                    1 => "Audit",
                    2 => "Enforced",
                    _ => $"Unknown({kernelCi})"
                };
                string userLabel = userCi switch
                {
                    0 => "Off",
                    1 => "Audit",
                    2 => "Enforced",
                    _ => $"Unknown({userCi})"
                };

                evidence.AppendLine($"  Kernel CI: {kernelLabel}");
                evidence.AppendLine($"  User-mode CI: {userLabel}");

                if (kernelCi >= 1)
                {
                    sb.AppendLine($"WDAC Code Integrity: Kernel={kernelLabel}, UserMode={userLabel}.");
                }
                else
                {
                    failCount++;
                    sb.AppendLine("FAIL: WDAC Code Integrity policy is not active.");
                }
            }

            if (!found)
            {
                evidence.AppendLine("  Win32_DeviceGuard not available.");
                sb.AppendLine("INFO: Device Guard WMI class not available. WDAC status unknown.");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
            sb.AppendLine("INFO: Could not query Device Guard (WDAC). May require admin or newer OS.");
        }
    }

    private static void CheckOfficeMacros(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[Office Macro Restrictions]");

        // Check VBAWarnings for each major Office app
        // VBAWarnings: 1=Enable all, 2=Disable with notification, 3=Disable except digitally signed, 4=Disable all
        string[] officeApps = ["Word", "Excel", "PowerPoint"];
        bool anyOfficeFound = false;
        bool allRestricted = true;

        foreach (string app in officeApps)
        {
            // Check multiple Office version paths (16.0 = Office 2016+/365)
            foreach (string version in new[] { "16.0", "15.0" })
            {
                string policyPath = $@"HKCU\SOFTWARE\Policies\Microsoft\Office\{version}\{app.ToLowerInvariant()}\Security";
                string userPath = $@"HKCU\SOFTWARE\Microsoft\Office\{version}\{app}\Security";

                int policyVal = RegistryHelper.GetValue<int>(policyPath, "VBAWarnings", -1);
                int userVal = RegistryHelper.GetValue<int>(userPath, "VBAWarnings", -1);

                int effective = policyVal != -1 ? policyVal : userVal;
                if (effective == -1) continue;

                anyOfficeFound = true;
                string label = effective switch
                {
                    1 => "Enable all macros (DANGEROUS)",
                    2 => "Disable with notification",
                    3 => "Disable except digitally signed",
                    4 => "Disable all without notification",
                    _ => $"Unknown({effective})"
                };

                evidence.AppendLine($"  {app} {version}: VBAWarnings={effective} ({label}){(policyVal != -1 ? " [via GPO]" : "")}");

                if (effective <= 1)
                {
                    allRestricted = false;
                }
            }
        }

        // Check Office macro block from internet (Office 2016+ GPO)
        int blockInternetMacros = RegistryHelper.GetValue<int>(
            @"HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security", "blockcontentexecutionfrominternet", -1);
        evidence.AppendLine($"  Block macros from internet: {(blockInternetMacros == 1 ? "Enabled" : blockInternetMacros == -1 ? "Not configured" : "Disabled")}");

        if (!anyOfficeFound)
        {
            sb.AppendLine("INFO: No Office macro settings detected (Office may not be installed).");
            failCount--; // Don't count as fail if Office isn't present
            totalChecks--;
        }
        else if (!allRestricted)
        {
            failCount++;
            sb.AppendLine("FAIL: Office macros are not fully restricted. At least one application allows all macros.");
        }
        else
        {
            sb.AppendLine("Office macros: Restricted (notifications or digital signature required).");
        }
    }

    private static void CheckSmartAppControl(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[Smart App Control]");

        // Smart App Control state stored in CI policy registry
        int sacState = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState", -1);

        string stateLabel = sacState switch
        {
            0 => "Off",
            1 => "Evaluation",
            2 => "On (Enforced)",
            _ => "Not available"
        };

        evidence.AppendLine($"  VerifiedAndReputablePolicyState = {sacState} ({stateLabel})");

        if (sacState == 2)
        {
            sb.AppendLine("Smart App Control: Enforced.");
        }
        else if (sacState == 1)
        {
            sb.AppendLine("Smart App Control: Evaluation mode (learning).");
        }
        else if (sacState == 0)
        {
            sb.AppendLine("INFO: Smart App Control is off. Once turned off it cannot be re-enabled without OS reinstall.");
        }
        else
        {
            sb.AppendLine("INFO: Smart App Control state not available (requires Windows 11 22H2+).");
            totalChecks--;
            failCount--;
        }
    }

    private static void CheckWindowsRecall(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[Windows Recall]");

        // DisableAIDataAnalysis = 1 means Recall is disabled via policy
        int disabledPolicy = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", -1);

        // Also check user-level setting
        int disabledUser = RegistryHelper.GetValue<int>(
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "DisableAIDataAnalysis", -1);

        evidence.AppendLine($"  Policy DisableAIDataAnalysis = {disabledPolicy}");
        evidence.AppendLine($"  User DisableAIDataAnalysis = {disabledUser}");

        if (disabledPolicy == 1 || disabledUser == 1)
        {
            sb.AppendLine("Windows Recall: Disabled.");
        }
        else if (disabledPolicy == -1 && disabledUser == -1)
        {
            // Recall may not be available on this system (pre-24H2 or non-Copilot+ hardware)
            sb.AppendLine("INFO: Windows Recall policy not configured (feature may not be available on this hardware).");
            totalChecks--;
        }
        else
        {
            failCount++;
            sb.AppendLine("FAIL: Windows Recall is enabled. Sensitive data may be continuously captured.");
        }
    }
}

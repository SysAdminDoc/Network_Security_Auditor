namespace NetworkSecurityAuditor.Checks.PoliciesStandards;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// PS01 - Security Policies: Check for security policy indicators. Report checklist status.
/// </summary>
public sealed class PS01_SecurityPoliciesCheck : ISecurityCheck
{
    public string Id => "PS01";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int indicators = 0;

            evidence.AppendLine("[Security Policy Indicators]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");

            // 1. Check if GPO is applied (indicates centralized policy management)
            ct.ThrowIfCancellationRequested();
            if (env.HasGPO)
            {
                indicators++;
                evidence.AppendLine("  Group Policy: Active");
                sb.AppendLine("Group Policy Objects are applied (centralized policy management detected).");
            }
            else
            {
                evidence.AppendLine("  Group Policy: Not detected");
            }

            // 2. Check for security policy settings via secedit
            ct.ThrowIfCancellationRequested();
            CheckSecurityPolicy(sb, evidence, ref indicators, ct);

            // 3. Check for Windows Security Baselines
            ct.ThrowIfCancellationRequested();
            CheckSecurityBaselines(sb, evidence, ref indicators);

            // 4. Check Intune/MDM
            if (env.IntuneManaged)
            {
                indicators++;
                evidence.AppendLine("\n  Intune MDM: Managed");
                sb.AppendLine("Device is Intune-managed (MDM policies may enforce security baseline).");
            }

            sb.AppendLine();
            sb.AppendLine($"Security policy indicators found: {indicators}");
            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Security Policy Review:");
            sb.AppendLine("  [ ] Written information security policy exists");
            sb.AppendLine("  [ ] Policy is approved by management and reviewed annually");
            sb.AppendLine("  [ ] Policy covers: access control, data classification, incident response");
            sb.AppendLine("  [ ] Policy covers: acceptable use, password requirements, remote access");
            sb.AppendLine("  [ ] Policy is communicated to all employees");
            sb.AppendLine("  [ ] Policy compliance is monitored and enforced");
            sb.AppendLine("  [ ] Policy exceptions require documented approval");
            sb.AppendLine("  [ ] Policy aligns with applicable compliance frameworks (NIST, CIS, HIPAA, etc.)");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Review written security policies " +
                "for completeness, currency, and management approval.");

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

    private static void CheckSecurityPolicy(StringBuilder sb, StringBuilder evidence,
        ref int indicators, CancellationToken ct)
    {
        evidence.AppendLine("\n[Local Security Policy Settings]");

        // Check password policy via registry
        int minPwdLen = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "MinimumPasswordLength", -1);

        if (minPwdLen >= 0)
        {
            evidence.AppendLine($"  Minimum password length: {minPwdLen}");
            if (minPwdLen >= 12)
                indicators++;
        }

        // Check account lockout
        int lockoutThreshold = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "LockoutThreshold", -1);

        if (lockoutThreshold >= 0)
        {
            evidence.AppendLine($"  Account lockout threshold: {lockoutThreshold}");
            if (lockoutThreshold is > 0 and <= 10)
                indicators++;
        }

        // Check if screen lock policy is configured
        int scrSaverActive = RegistryHelper.GetValue<int>(
            @"HKCU\Control Panel\Desktop",
            "ScreenSaveActive", -1);

        int scrSaverSecure = RegistryHelper.GetValue<int>(
            @"HKCU\Control Panel\Desktop",
            "ScreenSaverIsSecure", -1);

        if (scrSaverActive == 1 && scrSaverSecure == 1)
        {
            indicators++;
            evidence.AppendLine("  Screen saver with password lock: Enabled");
        }
        else
        {
            evidence.AppendLine($"  Screen saver: Active={scrSaverActive}, Secure={scrSaverSecure}");
        }
    }

    private static void CheckSecurityBaselines(StringBuilder sb, StringBuilder evidence, ref int indicators)
    {
        evidence.AppendLine("\n[Security Baseline Indicators]");

        // Check for Microsoft Security Compliance Toolkit
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\PolicyManager"))
        {
            evidence.AppendLine("  Microsoft PolicyManager: Present");
        }

        // Check for CIS benchmark indicators
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\CIS"))
        {
            indicators++;
            evidence.AppendLine("  CIS benchmark tools: Detected");
            sb.AppendLine("CIS benchmark tools detected.");
        }

        // Check for STIG compliance tools
        if (RegistryHelper.KeyExists(@"HKLM\SOFTWARE\DISA"))
        {
            indicators++;
            evidence.AppendLine("  DISA STIG tools: Detected");
            sb.AppendLine("DISA STIG compliance tools detected.");
        }
    }
}

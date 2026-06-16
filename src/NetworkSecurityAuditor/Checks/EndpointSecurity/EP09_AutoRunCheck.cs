namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP09 - AutoRun/AutoPlay: verify NoDriveTypeAutoRun and NoAutorun policies are set.
/// </summary>
public sealed class EP09_AutoRunCheck : ISecurityCheck
{
    public string Id => "EP09";

    // NoDriveTypeAutoRun value 255 (0xFF) = disable AutoRun for all drive types
    private const int AllDrivesDisabled = 255;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            // 1. Machine-level NoDriveTypeAutoRun
            ct.ThrowIfCancellationRequested();
            CheckNoDriveTypeAutoRun("HKLM", sb, evidence, ref hasIssue);

            // 2. User-level NoDriveTypeAutoRun
            ct.ThrowIfCancellationRequested();
            CheckNoDriveTypeAutoRun("HKCU", sb, evidence, ref hasIssue);

            // 3. NoAutorun policy (HKLM)
            ct.ThrowIfCancellationRequested();
            CheckNoAutorun(sb, evidence, ref hasIssue);

            // 4. AutoPlay behavior / DisableAutoplay
            ct.ThrowIfCancellationRequested();
            CheckAutoPlay(sb, evidence, ref hasIssue);

            if (!hasIssue)
            {
                sb.Insert(0, "AutoRun/AutoPlay is properly disabled across all drive types.\n");
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

    private static void CheckNoDriveTypeAutoRun(string hive, StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        string label = hive == "HKLM" ? "Machine" : "User";
        evidence.AppendLine($"[{label}-level NoDriveTypeAutoRun]");

        // Policy path takes precedence
        string policyPath = $@"{hive}\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        int policyVal = RegistryHelper.GetValue<int>(policyPath, "NoDriveTypeAutoRun", -1);

        evidence.AppendLine($"  {hive} Policies\\Explorer\\NoDriveTypeAutoRun = {(policyVal == -1 ? "not set" : $"0x{policyVal:X2} ({policyVal})")}");

        if (policyVal == -1)
        {
            hasIssue = true;
            sb.AppendLine($"FAIL: {label}-level NoDriveTypeAutoRun is not configured.");
        }
        else if (policyVal == AllDrivesDisabled)
        {
            sb.AppendLine($"{label}-level NoDriveTypeAutoRun = 0xFF (all drive types disabled).");
        }
        else if ((policyVal & 0x80) != 0)
        {
            // Bit 7 = unknown drive types; if set along with most others, partial coverage
            sb.AppendLine($"INFO: {label}-level NoDriveTypeAutoRun = 0x{policyVal:X2}. Not all drive types are disabled (recommended: 0xFF).");
        }
        else
        {
            hasIssue = true;
            sb.AppendLine($"FAIL: {label}-level NoDriveTypeAutoRun = 0x{policyVal:X2} does not disable all drive types (expected 0xFF/255).");
        }
    }

    private static void CheckNoAutorun(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[NoAutorun Policy]");

        // "Turn off Autoplay" GPO sets NoAutorun = 1
        int noAutorun = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun", -1);

        evidence.AppendLine($"  HKLM NoAutorun = {(noAutorun == -1 ? "not set" : noAutorun.ToString())}");

        if (noAutorun == 1)
        {
            sb.AppendLine("NoAutorun policy: Enabled (autorun.inf commands are ignored).");
        }
        else
        {
            hasIssue = true;
            sb.AppendLine("FAIL: NoAutorun policy is not set. The system honors autorun.inf files (USB malware vector).");
        }
    }

    private static void CheckAutoPlay(StringBuilder sb, StringBuilder evidence, ref bool hasIssue)
    {
        evidence.AppendLine("\n[AutoPlay (Turn off Autoplay)]");

        // NoDriveAutoRun policy via GP
        int disableAutoplay = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveAutoRun", -1);

        evidence.AppendLine($"  HKLM NoDriveAutoRun = {(disableAutoplay == -1 ? "not set" : $"0x{disableAutoplay:X8}")}");

        // HonorAutorunSetting - when set to 0, forces autorun to be honored regardless
        int honorSetting = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "HonorAutorunSetting", -1);

        evidence.AppendLine($"  HKLM HonorAutorunSetting = {(honorSetting == -1 ? "not set" : honorSetting.ToString())}");

        if (honorSetting == 0)
        {
            hasIssue = true;
            sb.AppendLine("FAIL: HonorAutorunSetting is disabled (0). AutoRun restrictions may be bypassed.");
        }
    }
}

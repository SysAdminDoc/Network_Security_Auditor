namespace NetworkSecurityAuditor.Checks.LoggingMonitoring;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// LM03 - Advanced audit policy, PowerShell logging, command-line auditing, CIS L1 hardening items.
/// </summary>
public sealed class LM03_AuditPolicyCheck : ISecurityCheck
{
    public string Id => "LM03";

    // CIS L1 required subcategories and their expected settings
    private static readonly (string Subcategory, string Expected)[] CisAuditSubcategories =
    [
        ("Credential Validation", "Success and Failure"),
        ("Application Group Management", "Success and Failure"),
        ("Security Group Management", "Success"),
        ("User Account Management", "Success and Failure"),
        ("Process Creation", "Success"),
        ("Account Lockout", "Failure"),
        ("Logoff", "Success"),
        ("Logon", "Success and Failure"),
        ("Other Logon/Logoff Events", "Success and Failure"),
        ("Special Logon", "Success"),
        ("Audit Policy Change", "Success"),
        ("Authentication Policy Change", "Success"),
        ("Sensitive Privilege Use", "Success and Failure"),
        ("Security State Change", "Success"),
        ("Security System Extension", "Success"),
        ("System Integrity", "Success and Failure"),
    ];

    // CIS L1 registry hardening items
    private static readonly (string KeyPath, string ValueName, int Expected, string Description)[] CisRegistryItems =
    [
        (@"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application", "MaxSize", 32768,
            "Application event log >= 32768 KB"),
        (@"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "MaxSize", 196608,
            "Security event log >= 196608 KB"),
        (@"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System", "MaxSize", 32768,
            "System event log >= 32768 KB"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1,
            "UAC: Admin Approval Mode enabled"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 2,
            "UAC: Prompt for consent on secure desktop"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1,
            "UAC: Switch to secure desktop when prompting"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous", 1,
            "Restrict anonymous enumeration of SAM accounts"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM", 1,
            "Restrict anonymous enumeration of SAM accounts and shares"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "EveryoneIncludesAnonymous", 0,
            "Do not allow anonymous SID/Name translation"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionShares", 0,
            "No null session shares"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken", 1,
            "UAC: Filter admin token for built-in Administrator"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", 1,
            "Limit blank password use to console only"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "ForceGuest", 0,
            "Sharing model: Classic"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "RequireSignOrSeal", 1,
            "Domain member: Digitally encrypt/sign secure channel data"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "SealSecureChannel", 1,
            "Domain member: Digitally encrypt secure channel data"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "SignSecureChannel", 1,
            "Domain member: Digitally sign secure channel data"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs", 900,
            "Machine inactivity limit <= 900 seconds"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText", -1,
            "Interactive logon: Message text (should be set)"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", 1,
            "SMB server: Enable security signature"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", 1,
            "SMB client: Enable security signature"),
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. Advanced audit policy via auditpol
            ct.ThrowIfCancellationRequested();
            CheckAuditPolicy(sb, evidence, ref failCount, ref totalChecks, ct);

            // 2. PowerShell logging settings
            ct.ThrowIfCancellationRequested();
            CheckPowerShellLogging(sb, evidence, ref failCount, ref totalChecks);

            // 3. Command-line in process creation events (4688)
            ct.ThrowIfCancellationRequested();
            CheckCommandLineAuditing(sb, evidence, ref failCount, ref totalChecks);

            // 4. PowerShell v2 engine status
            ct.ThrowIfCancellationRequested();
            CheckPSv2(sb, evidence, ref failCount, ref totalChecks);

            // 5. CIS L1 registry hardening items
            ct.ThrowIfCancellationRequested();
            CheckCisRegistry(sb, evidence, ref failCount, ref totalChecks);

            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount <= totalChecks / 3 ? CheckStatus.Partial : CheckStatus.Fail;

            sb.Insert(0, $"Audit policy check: {totalChecks - failCount}/{totalChecks} items compliant.\n");

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

    private static void CheckAuditPolicy(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks, CancellationToken ct)
    {
        evidence.AppendLine("[Advanced Audit Policy]");

        try
        {
            string csv = RunCommand("auditpol", "/get /category:* /r", ct);
            evidence.AppendLine(csv.Length > 2000 ? csv[..2000] + "\n...(truncated)" : csv);

            // Parse CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,...
            var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var (subcategory, expected) in CisAuditSubcategories)
            {
                totalChecks++;
                ct.ThrowIfCancellationRequested();

                bool found = false;
                foreach (var line in lines)
                {
                    if (!line.Contains(subcategory, StringComparison.OrdinalIgnoreCase)) continue;

                    found = true;
                    var fields = line.Split(',');
                    // Inclusion Setting is typically field index 4
                    string setting = fields.Length > 4 ? fields[4].Trim() : "Unknown";

                    if (!setting.Contains("Success", StringComparison.OrdinalIgnoreCase) &&
                        expected.Contains("Success", StringComparison.OrdinalIgnoreCase))
                    {
                        failCount++;
                        sb.AppendLine($"FAIL: Audit '{subcategory}' = '{setting}' (expected: {expected}).");
                    }
                    else if (expected.Contains("Failure", StringComparison.OrdinalIgnoreCase) &&
                             !setting.Contains("Failure", StringComparison.OrdinalIgnoreCase))
                    {
                        failCount++;
                        sb.AppendLine($"FAIL: Audit '{subcategory}' missing Failure auditing (current: {setting}).");
                    }
                    break;
                }

                if (!found)
                {
                    failCount++;
                    sb.AppendLine($"WARNING: Audit subcategory '{subcategory}' not found in policy output.");
                }
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  auditpol error: {ex.Message}");
            sb.AppendLine("Could not query audit policy (requires administrator privileges).");
            failCount += CisAuditSubcategories.Length;
            totalChecks += CisAuditSubcategories.Length;
        }
    }

    private static void CheckPowerShellLogging(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        evidence.AppendLine("\n[PowerShell Logging]");
        const string psKey = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell";

        // Script Block Logging
        totalChecks++;
        int scriptBlock = RegistryHelper.GetValue<int>($@"{psKey}\ScriptBlockLogging", "EnableScriptBlockLogging", 0);
        evidence.AppendLine($"  ScriptBlockLogging = {scriptBlock}");
        if (scriptBlock != 1)
        {
            failCount++;
            sb.AppendLine("FAIL: PowerShell Script Block Logging is not enabled.");
        }

        // Module Logging
        totalChecks++;
        int moduleLogging = RegistryHelper.GetValue<int>($@"{psKey}\ModuleLogging", "EnableModuleLogging", 0);
        evidence.AppendLine($"  ModuleLogging = {moduleLogging}");
        if (moduleLogging != 1)
        {
            failCount++;
            sb.AppendLine("FAIL: PowerShell Module Logging is not enabled.");
        }

        // Transcription
        totalChecks++;
        int transcription = RegistryHelper.GetValue<int>($@"{psKey}\Transcription", "EnableTranscripting", 0);
        evidence.AppendLine($"  Transcription = {transcription}");
        if (transcription != 1)
        {
            sb.AppendLine("WARNING: PowerShell Transcription is not enabled (recommended for forensics).");
            // Not a hard fail per CIS L1, but flagged
        }
    }

    private static void CheckCommandLineAuditing(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[Command-Line in Process Creation Events]");

        int cmdLine = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled", 0);

        evidence.AppendLine($"  ProcessCreationIncludeCmdLine_Enabled = {cmdLine}");

        if (cmdLine != 1)
        {
            failCount++;
            sb.AppendLine("FAIL: Command-line auditing in event 4688 is not enabled.");
        }
        else
        {
            sb.AppendLine("PASS: Command-line data is included in process creation events (4688).");
        }
    }

    private static void CheckPSv2(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        evidence.AppendLine("\n[PowerShell v2 Engine]");

        // Check Windows feature state
        bool psv2Installed = RegistryHelper.KeyExists(
            @"HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine");

        // Also check DISM-style feature state
        int featureState = RegistryHelper.GetValue<int>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Microsoft-Windows-PowerShell-V2-Client-Package~*",
            "CurrentState", -1);

        evidence.AppendLine($"  PowerShell v2 engine key exists = {psv2Installed}");
        evidence.AppendLine($"  CBS feature state = {featureState}");

        // PSv2 can be used to bypass AMSI/ScriptBlock logging
        if (psv2Installed)
        {
            failCount++;
            sb.AppendLine("FAIL: PowerShell v2 engine is installed. It bypasses AMSI, Script Block Logging, and Constrained Language Mode.");
        }
        else
        {
            sb.AppendLine("PASS: PowerShell v2 engine is not installed.");
        }
    }

    private static void CheckCisRegistry(StringBuilder sb, StringBuilder evidence,
        ref int failCount, ref int totalChecks)
    {
        evidence.AppendLine("\n[CIS L1 Registry Hardening]");
        int cisPass = 0;
        int cisFail = 0;

        foreach (var (keyPath, valueName, expected, description) in CisRegistryItems)
        {
            totalChecks++;

            if (expected == -1)
            {
                // Special case: just check if value is set (non-empty string)
                string? val = RegistryHelper.GetValue<string>(keyPath, valueName, null);
                bool isSet = !string.IsNullOrWhiteSpace(val);
                evidence.AppendLine($"  {description}: {(isSet ? "SET" : "NOT SET")}");
                if (!isSet)
                {
                    cisFail++;
                    failCount++;
                }
                else
                {
                    cisPass++;
                }
                continue;
            }

            int actual = RegistryHelper.GetValue<int>(keyPath, valueName, -999);
            bool pass;

            if (description.Contains(">="))
            {
                pass = actual >= expected;
            }
            else if (description.Contains("<="))
            {
                pass = actual <= expected && actual >= 0;
            }
            else
            {
                pass = actual == expected;
            }

            evidence.AppendLine($"  {description}: actual={actual}, expected={expected}, {(pass ? "PASS" : "FAIL")}");

            if (!pass)
            {
                cisFail++;
                failCount++;
            }
            else
            {
                cisPass++;
            }
        }

        sb.AppendLine($"CIS L1 registry hardening: {cisPass}/{cisPass + cisFail} items compliant.");
        if (cisFail > 0)
            sb.AppendLine($"  {cisFail} CIS L1 hardening items are non-compliant (see evidence for details).");
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        return CommandRunner.RunForOutput(fileName, arguments, TimeSpan.FromSeconds(30), ct);
    }
}

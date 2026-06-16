namespace NetworkSecurityAuditor.Checks.PoliciesStandards;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// PS02 - Acceptable Use Policy: Checklist check. Report that AUP needs manual verification.
/// </summary>
public sealed class PS02_AcceptableUseCheck : ISecurityCheck
{
    public string Id => "PS02";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            evidence.AppendLine("[Acceptable Use Policy Review]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");

            // Check for logon banner (indicates policy enforcement)
            bool hasBanner = CheckLogonBanner(evidence);

            if (hasBanner)
            {
                sb.AppendLine("Logon banner/legal notice detected (indicates AUP enforcement).");
            }

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Acceptable Use Policy:");
            sb.AppendLine("  [ ] Written Acceptable Use Policy (AUP) exists");
            sb.AppendLine("  [ ] AUP covers: internet usage, email, personal devices, social media");
            sb.AppendLine("  [ ] AUP covers: data handling, software installation, remote access");
            sb.AppendLine("  [ ] AUP covers: monitoring disclosure and consent");
            sb.AppendLine("  [ ] All employees have signed/acknowledged the AUP");
            sb.AppendLine("  [ ] AUP is included in employee onboarding");
            sb.AppendLine("  [ ] AUP violations have defined consequences");
            sb.AppendLine("  [ ] AUP is reviewed and updated annually");
            sb.AppendLine("  [ ] Logon banner displays legal notice / AUP reminder");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Review the Acceptable Use Policy " +
                "document and employee acknowledgment records.");

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

    private static bool CheckLogonBanner(StringBuilder evidence)
    {
        evidence.AppendLine("\n[Logon Banner Check]");

        string? caption = Services.RegistryHelper.GetValue<string>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LegalNoticeCaption", null);

        string? text = Services.RegistryHelper.GetValue<string>(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LegalNoticeText", null);

        bool hasBanner = !string.IsNullOrWhiteSpace(caption) || !string.IsNullOrWhiteSpace(text);

        evidence.AppendLine($"  Legal notice caption: {(string.IsNullOrEmpty(caption) ? "(none)" : caption)}");
        evidence.AppendLine($"  Legal notice text: {(string.IsNullOrEmpty(text) ? "(none)" : Truncate(text, 200))}");

        return hasBanner;
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }
}

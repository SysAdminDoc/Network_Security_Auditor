namespace NetworkSecurityAuditor.Checks.BackupRecovery;

using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// BR08 - SaaS Backup: Checklist check. Report that SaaS backup needs manual verification
/// for M365/Google Workspace.
/// </summary>
public sealed class BR08_SaasBackupCheck : ISecurityCheck
{
    public string Id => "BR08";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            evidence.AppendLine("[SaaS Backup Review]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");
            evidence.AppendLine($"  Host: {env.ComputerName}");
            evidence.AppendLine($"  Domain-joined: {env.IsDomainJoined}");
            evidence.AppendLine($"  Azure AD Joined: {env.AzureADJoined}");
            evidence.AppendLine($"  Tenant: {(string.IsNullOrEmpty(env.TenantName) ? "N/A" : env.TenantName)}");

            // Detect M365/Azure indicators
            bool m365Likely = env.AzureADJoined || !string.IsNullOrEmpty(env.TenantName);

            if (m365Likely)
            {
                sb.AppendLine($"Microsoft 365 / Azure AD tenant detected: {env.TenantName}");
                sb.AppendLine("M365 data (Exchange, OneDrive, SharePoint, Teams) is NOT automatically backed up by Microsoft.");
                sb.AppendLine("Microsoft's shared responsibility model requires customers to protect their own data.");
            }

            // Check for SaaS backup software indicators
            CheckSaasBackupSoftware(sb, evidence);

            sb.AppendLine();
            sb.AppendLine("CHECKLIST - SaaS Backup Review:");
            sb.AppendLine("  [ ] Microsoft 365 data (Exchange, OneDrive, SharePoint, Teams) is backed up");
            sb.AppendLine("  [ ] Google Workspace data (Gmail, Drive, Calendar) is backed up (if applicable)");
            sb.AppendLine("  [ ] SaaS backup solution is deployed (Veeam for M365, Datto SaaS, Spanning, etc.)");
            sb.AppendLine("  [ ] SaaS backup retention meets compliance requirements");
            sb.AppendLine("  [ ] SaaS backup restores have been tested");
            sb.AppendLine("  [ ] Salesforce/other critical SaaS data is backed up (if applicable)");
            sb.AppendLine("  [ ] SaaS backup covers all licensed users");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview IT to verify SaaS backup " +
                "coverage, solution deployed, and restore testing results.");

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

    private static void CheckSaasBackupSoftware(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[SaaS Backup Software Indicators]");

        var saasBackup = new Dictionary<string, string>
        {
            { @"HKLM\SOFTWARE\Veeam\Veeam Backup for Microsoft 365", "Veeam for M365" },
            { @"HKLM\SOFTWARE\Spanning", "Spanning Backup" },
            { @"HKLM\SOFTWARE\Barracuda\CloudToCloud", "Barracuda Cloud-to-Cloud" },
            { @"HKLM\SOFTWARE\AvePoint", "AvePoint Cloud Backup" },
        };

        bool found = false;
        foreach (var (path, label) in saasBackup)
        {
            if (Services.RegistryHelper.KeyExists(path))
            {
                found = true;
                evidence.AppendLine($"  FOUND: {label}");
                sb.AppendLine($"SaaS backup software detected: {label}");
            }
        }

        if (!found)
            evidence.AppendLine("  No SaaS backup software detected on this host.");
    }
}

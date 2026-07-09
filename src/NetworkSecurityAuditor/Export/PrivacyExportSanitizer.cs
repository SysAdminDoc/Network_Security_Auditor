using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class PrivacyExportSanitizer
{
    public static PrivacyRedactor CreateRedactor(
        bool enabled,
        EnvironmentInfo env,
        string userName,
        string clientName = "")
    {
        return new PrivacyRedactor(enabled, env.ComputerName, env.DomainName, userName, clientName, env.TenantName);
    }

    public static EnvironmentInfo RedactEnvironment(EnvironmentInfo env, PrivacyRedactor redactor)
    {
        if (!redactor.IsEnabled) return env;

        return new EnvironmentInfo
        {
            ComputerName = redactor.Redact(env.ComputerName),
            IsAdmin = env.IsAdmin,
            OSCaption = redactor.Redact(env.OSCaption),
            IsServer = env.IsServer,
            IsDomainJoined = env.IsDomainJoined,
            DomainName = redactor.Redact(env.DomainName),
            HasAD = env.HasAD,
            HasDNS = env.HasDNS,
            HasGPO = env.HasGPO,
            HasDefender = env.HasDefender,
            HasSMB = env.HasSMB,
            HasBitLocker = env.HasBitLocker,
            HasAppLocker = env.HasAppLocker,
            WinRMRunning = env.WinRMRunning,
            JoinType = redactor.Redact(env.JoinType),
            AzureADJoined = env.AzureADJoined,
            IntuneManaged = env.IntuneManaged,
            TenantName = redactor.Redact(env.TenantName),
            OSBuild = env.OSBuild,
            OSVersion = env.OSVersion,
            IsServer2025OrLater = env.IsServer2025OrLater,
            HasWindowsLAPS = env.HasWindowsLAPS,
            HasLegacyLAPS = env.HasLegacyLAPS,
            PSVersion = env.PSVersion
        };
    }

    public static List<CheckItemViewModel> RedactChecks(
        IEnumerable<CheckItemViewModel> checks,
        PrivacyRedactor redactor)
    {
        if (!redactor.IsEnabled) return checks.ToList();

        var redacted = new List<CheckItemViewModel>();
        foreach (var check in checks)
        {
            var copy = CheckItemViewModel.FromMetadata(
                CheckCatalog.All.GetValueOrDefault(check.Id)
                ?? new CheckMetadata
                {
                    Id = check.Id,
                    Category = check.Category,
                    Label = check.Label,
                    Hint = "",
                    Severity = check.Severity,
                    Weight = check.Weight,
                    Type = CheckType.Local,
                    RiskTier = RiskTier.ReadOnly,
                    Compliance = check.Compliance
                });
            copy.Status = check.Status;
            copy.Findings = redactor.Redact(check.Findings);
            copy.Evidence = redactor.Redact(check.Evidence);
            copy.Notes = redactor.Redact(check.Notes);
            copy.RemediationAssignee = redactor.Redact(check.RemediationAssignee);
            copy.RemediationDueDate = check.RemediationDueDate;
            copy.DurationMs = check.DurationMs;
            redacted.Add(copy);
        }

        return redacted;
    }

    public static IReadOnlyDictionary<string, RiskWaiver> RedactActiveWaivers(
        WaiverStore? waiverStore,
        PrivacyRedactor redactor)
    {
        if (waiverStore is null)
            return new Dictionary<string, RiskWaiver>(StringComparer.OrdinalIgnoreCase);

        var waivers = new Dictionary<string, RiskWaiver>(StringComparer.OrdinalIgnoreCase);
        foreach (var waiver in waiverStore.Waivers.Where(w => w.IsActive))
        {
            waivers[waiver.CheckId] = redactor.IsEnabled
                ? new RiskWaiver
                {
                    CheckId = waiver.CheckId,
                    Justification = redactor.Redact(waiver.Justification),
                    ApprovedBy = redactor.Redact(waiver.ApprovedBy),
                    ApprovedDate = waiver.ApprovedDate,
                    ExpirationDate = waiver.ExpirationDate
                }
                : waiver;
        }

        return waivers;
    }

    public static IntuneStigAuditImport? RedactIntuneStigAudit(
        IntuneStigAuditImport? import,
        PrivacyRedactor redactor)
    {
        if (import is null || !redactor.IsEnabled)
            return import;

        return new IntuneStigAuditImport
        {
            SchemaVersion = import.SchemaVersion,
            Source = import.Source,
            SourceUrl = import.SourceUrl,
            BaselineName = import.BaselineName,
            BaselineVersion = import.BaselineVersion,
            TenantId = redactor.Redact(import.TenantId),
            PolicyId = import.PolicyId,
            ExportedAtUtc = import.ExportedAtUtc,
            ImportedAtUtc = import.ImportedAtUtc,
            ImportStatus = import.ImportStatus,
            Findings = import.Findings.Select(finding => new IntuneStigAuditFinding
            {
                DeviceName = redactor.Redact(finding.DeviceName),
                DeviceId = redactor.Redact(finding.DeviceId),
                SettingId = finding.SettingId,
                SettingName = finding.SettingName,
                ReferenceId = finding.ReferenceId,
                Severity = finding.Severity,
                Status = finding.Status,
                XccdfResult = finding.XccdfResult,
                LastCheckInUtc = finding.LastCheckInUtc,
                SourcePolicyId = finding.SourcePolicyId,
                SourceTenantId = redactor.Redact(finding.SourceTenantId)
            }).ToList()
        };
    }
}

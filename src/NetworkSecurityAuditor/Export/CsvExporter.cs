using System.Globalization;
using System.Text;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class CsvExporter
{
    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        IntuneStigAuditImport? intuneStigAudit = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"# Host: {Escape(env.ComputerName)} | Score: {overallScore}/100 ({grade}) | Generated: {DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC");
        sb.AppendLine("CheckID,Category,Label,Severity,Status,Findings,Evidence,Notes,CIS,NIST,CMMC,HIPAA,PCI,SOC2,ISO27001,STIG,FedRAMP,E8,CyberEssentials,MitreTactics,MitreTechniques,D3FendStages,D3FendTechniques");

        foreach (var check in checks)
        {
            var compliance = FrameworkMappings.All.GetValueOrDefault(check.Id);
            var mitre = MitreMappings.All.GetValueOrDefault(check.Id);
            var defend = D3FendMappings.All.GetValueOrDefault(check.Id);

            sb.Append(Escape(check.Id)).Append(',');
            sb.Append(Escape(check.Category)).Append(',');
            sb.Append(Escape(check.Label)).Append(',');
            sb.Append(Escape(check.Severity.ToString())).Append(',');
            sb.Append(Escape(DisplayStatus(check.Status))).Append(',');
            sb.Append(Escape(check.Findings)).Append(',');
            sb.Append(Escape(check.Evidence)).Append(',');
            sb.Append(Escape(check.Notes)).Append(',');
            sb.Append(Escape(compliance?.CIS ?? "")).Append(',');
            sb.Append(Escape(compliance?.NIST ?? "")).Append(',');
            sb.Append(Escape(compliance?.CMMC ?? "")).Append(',');
            sb.Append(Escape(compliance?.HIPAA ?? "")).Append(',');
            sb.Append(Escape(compliance?.PCI ?? "")).Append(',');
            sb.Append(Escape(compliance?.SOC2 ?? "")).Append(',');
            sb.Append(Escape(compliance?.ISO27001 ?? "")).Append(',');
            sb.Append(Escape(compliance?.STIG ?? "")).Append(',');
            sb.Append(Escape(compliance?.FedRAMP ?? "")).Append(',');
            sb.Append(Escape(compliance?.E8 ?? "")).Append(',');
            sb.Append(Escape(compliance?.CyberEssentials ?? "")).Append(',');
            sb.Append(Escape(mitre is not null ? string.Join("; ", mitre.Tactics) : "")).Append(',');
            sb.Append(Escape(mitre is not null ? string.Join("; ", mitre.Techniques) : "")).Append(',');
            sb.Append(Escape(defend is not null ? string.Join("; ", defend.Stages) : "")).Append(',');
            sb.Append(Escape(defend is not null ? string.Join("; ", defend.Techniques) : ""));
            sb.AppendLine();
        }

        if (intuneStigAudit is not null)
        {
            sb.AppendLine("# Intune STIG audit baseline evidence");
            sb.AppendLine("EvidenceType,Source,BaselineVersion,DeviceName,SettingId,ReferenceId,Severity,Status,XccdfResult,LastCheckInUtc,PolicyId,SourceUrl");
            foreach (var finding in intuneStigAudit.Findings)
            {
                sb.Append(Escape("IntuneSTIG")).Append(',');
                sb.Append(Escape(intuneStigAudit.Source)).Append(',');
                sb.Append(Escape(intuneStigAudit.BaselineVersion)).Append(',');
                sb.Append(Escape(finding.DeviceName)).Append(',');
                sb.Append(Escape(finding.SettingId)).Append(',');
                sb.Append(Escape(finding.ReferenceId)).Append(',');
                sb.Append(Escape(finding.Severity)).Append(',');
                sb.Append(Escape(finding.Status)).Append(',');
                sb.Append(Escape(finding.XccdfResult)).Append(',');
                sb.Append(Escape(finding.LastCheckInUtc)).Append(',');
                sb.Append(Escape(finding.SourcePolicyId)).Append(',');
                sb.Append(Escape(intuneStigAudit.SourceUrl));
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    internal static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";

        var sanitized = value;
        bool formulaPrefixed = false;
        if (StartsWithSpreadsheetFormulaTrigger(sanitized))
        {
            sanitized = "'" + sanitized;
            formulaPrefixed = true;
        }

        if (formulaPrefixed || sanitized.Contains('"') || sanitized.Contains(',') ||
            sanitized.Contains('\n') || sanitized.Contains('\r'))
        {
            return "\"" + sanitized.Replace("\"", "\"\"") + "\"";
        }

        return sanitized;
    }

    private static string DisplayStatus(CheckStatus status) => status switch
    {
        CheckStatus.NotAssessed => "Not assessed",
        CheckStatus.NA => "N/A",
        _ => status.ToString()
    };

    private static bool StartsWithSpreadsheetFormulaTrigger(string value)
    {
        if (value.Length == 0)
            return false;

        if (value[0] is '\t' or '\r')
            return true;

        foreach (var c in value)
        {
            if (char.IsWhiteSpace(c))
                continue;

            return c is '=' or '+' or '-' or '@';
        }

        return false;
    }
}

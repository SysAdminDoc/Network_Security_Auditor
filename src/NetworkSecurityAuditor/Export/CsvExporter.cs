using System.Collections.ObjectModel;
using System.Text;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class CsvExporter
{
    public static string Export(
        ObservableCollection<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade)
    {
        var sb = new StringBuilder();

        sb.AppendLine("CheckID,Category,Label,Severity,Status,Findings,Evidence,Notes,NIST,CMMC,PCI,SOC2,ISO27001,STIG,FedRAMP");

        foreach (var check in checks)
        {
            var compliance = FrameworkMappings.All.GetValueOrDefault(check.Id);

            sb.Append(Escape(check.Id)).Append(',');
            sb.Append(Escape(check.Category)).Append(',');
            sb.Append(Escape(check.Label)).Append(',');
            sb.Append(Escape(check.Severity.ToString())).Append(',');
            sb.Append(Escape(check.Status.ToString())).Append(',');
            sb.Append(Escape(check.Findings)).Append(',');
            sb.Append(Escape(check.Evidence)).Append(',');
            sb.Append(Escape(check.Notes)).Append(',');
            sb.Append(Escape(compliance?.NIST ?? "")).Append(',');
            sb.Append(Escape(compliance?.CMMC ?? "")).Append(',');
            sb.Append(Escape(compliance?.PCI ?? "")).Append(',');
            sb.Append(Escape(compliance?.SOC2 ?? "")).Append(',');
            sb.Append(Escape(compliance?.ISO27001 ?? "")).Append(',');
            sb.Append(Escape(compliance?.STIG ?? "")).Append(',');
            sb.Append(Escape(compliance?.FedRAMP ?? ""));
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";

        var sanitized = value;
        if (sanitized.StartsWith('=') || sanitized.StartsWith('+') ||
            sanitized.StartsWith('-') || sanitized.StartsWith('@'))
        {
            sanitized = "'" + sanitized;
        }

        if (sanitized.Contains('"') || sanitized.Contains(',') ||
            sanitized.Contains('\n') || sanitized.Contains('\r'))
        {
            return "\"" + sanitized.Replace("\"", "\"\"") + "\"";
        }

        return sanitized;
    }
}

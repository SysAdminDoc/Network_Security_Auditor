namespace NetworkSecurityAuditor.Models;

public sealed class AuditOptions
{
    public bool Silent { get; set; }
    public ScanProfileType ScanProfile { get; set; } = ScanProfileType.Full;
    public string OutputPath { get; set; } = "";
    public ReportTier ReportTier { get; set; } = ReportTier.All;
    public bool ReadOnly { get; set; } = true;
    public string Client { get; set; } = "";
    public string Auditor { get; set; } = "";
    public bool ExportJSON { get; set; }
    public bool ExportCSV { get; set; }
    public bool ExportJSONL { get; set; }
    public bool PrivacyMode { get; set; }
    public bool NoRmmWrite { get; set; }
    public bool NoInternet { get; set; }
    public bool NoElevate { get; set; }
    public bool NoRegistryWrite { get; set; }
    public int CheckTimeoutSeconds { get; set; } = 90;
}

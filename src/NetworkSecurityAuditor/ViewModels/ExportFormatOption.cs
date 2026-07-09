namespace NetworkSecurityAuditor.ViewModels;

public enum ExportFormatKind
{
    Html,
    Pdf,
    Json,
    Csv,
    Jsonl,
    Sarif,
    Navigator,
    DefectDojo,
    Ocsf,
    Oscal,
    OscalPoam,
    Intune,
    ComplianceSummary,
    SiemContentPack,
    CmmcHtml,
    CmmcJson
}

public sealed record ExportFormatOption(
    ExportFormatKind Kind,
    string DisplayName,
    string FileSuffix,
    string Extension,
    bool IsFolderExport = false)
{
    public override string ToString() => DisplayName;
}

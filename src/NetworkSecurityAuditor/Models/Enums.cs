namespace NetworkSecurityAuditor.Models;

public enum CheckStatus
{
    NotAssessed,
    Pass,
    Partial,
    Fail,
    NA,
    /// <summary>The check threw or timed out. Not scored; counted in coverage and listed as a limitation.</summary>
    Error
}

public static class CheckStatusExtensions
{
    /// <summary>
    /// Pass, Partial and Fail are scored. NotAssessed (no answer yet), NA (doesn't apply) and Error
    /// (the check couldn't run) stay out of every score and denominator.
    /// </summary>
    public static bool IsScored(this CheckStatus status) =>
        status is CheckStatus.Pass or CheckStatus.Partial or CheckStatus.Fail;
}

public enum Severity
{
    Low = 3,
    Medium = 5,
    High = 7,
    Critical = 10
}

public enum CheckType
{
    Local,
    AD
}

public enum RiskTier
{
    ReadOnly = 0,
    RemoteRead = 1,
    Probing = 2,
    Modifying = 3
}

public enum EvidenceMode
{
    Automated,
    Heuristic,
    Checklist,
    InterviewRequired,
    ExternalRequired,
    Unknown
}

public enum ScanProfileType
{
    Quick,
    Standard,
    Full,
    ADOnly,
    LocalOnly,
    Cloud,
    HIPAA,
    PCI,
    CMMC,
    E8,
    CyberEssentials,
    SOC2,
    ISO27001,
    STIG,
    FedRAMP
}

public enum ReportTier
{
    Executive,
    Management,
    Technical,
    All
}

public enum ExitCode
{
    Green = 0,
    ImmediateAlert = 1,
    ReviewNeeded = 2,
    ComplianceAlert = 3,
    InputPathUnavailable = 64,
    NoScorableChecks = 65,
    DiagnosticsDegraded = 66,
    DiagnosticsBlocked = 67,
    AlreadyRunning = 68,
    /// <summary>A headless scan stopped early by Ctrl+C or its deadline. Its reports hold partial results.</summary>
    RunIncomplete = 69
}

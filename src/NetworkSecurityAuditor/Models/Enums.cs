namespace NetworkSecurityAuditor.Models;

public enum CheckStatus
{
    NotAssessed,
    Pass,
    Partial,
    Fail,
    NA
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
    NoScorableChecks = 65
}

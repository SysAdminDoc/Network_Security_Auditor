namespace NetworkSecurityAuditor.Models;

public sealed class IntuneStigAuditImport
{
    public string SchemaVersion { get; set; } = "1.0";
    public string Source { get; set; } = "Intune STIG audit baseline";
    public string SourceUrl { get; set; } = "https://learn.microsoft.com/en-us/intune/device-security/security-baselines/stig-audit-baseline";
    public string BaselineName { get; set; } = "";
    public string BaselineVersion { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string PolicyId { get; set; } = "";
    public string ExportedAtUtc { get; set; } = "";
    public string ImportedAtUtc { get; set; } = DateTime.UtcNow.ToString("o");
    public string ImportStatus { get; set; } = "Imported";
    public List<IntuneStigAuditFinding> Findings { get; set; } = [];

    public IntuneStigAuditSummary Summary => new()
    {
        Total = Findings.Count,
        Pass = Findings.Count(f => f.Status.Equals("Pass", StringComparison.OrdinalIgnoreCase)),
        Fail = Findings.Count(f => f.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase)),
        NotApplicable = Findings.Count(f => f.Status.Equals("NotApplicable", StringComparison.OrdinalIgnoreCase)),
        Error = Findings.Count(f => f.Status.Equals("Error", StringComparison.OrdinalIgnoreCase)),
        Conflict = Findings.Count(f => f.Status.Equals("Conflict", StringComparison.OrdinalIgnoreCase)),
        Unknown = Findings.Count(f => f.Status.Equals("Unknown", StringComparison.OrdinalIgnoreCase)),
        NotLicensed = Findings.Count(f => f.Status.Equals("NotLicensed", StringComparison.OrdinalIgnoreCase)),
        NotPermitted = Findings.Count(f => f.Status.Equals("NotPermitted", StringComparison.OrdinalIgnoreCase))
    };
}

public sealed class IntuneStigAuditFinding
{
    public string DeviceName { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string SettingId { get; set; } = "";
    public string SettingName { get; set; } = "";
    public string ReferenceId { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Status { get; set; } = "Unknown";
    public string XccdfResult { get; set; } = "unknown";
    public string LastCheckInUtc { get; set; } = "";
    public string SourcePolicyId { get; set; } = "";
    public string SourceTenantId { get; set; } = "";
}

public sealed class IntuneStigAuditSummary
{
    public int Total { get; set; }
    public int Pass { get; set; }
    public int Fail { get; set; }
    public int NotApplicable { get; set; }
    public int Error { get; set; }
    public int Conflict { get; set; }
    public int Unknown { get; set; }
    public int NotLicensed { get; set; }
    public int NotPermitted { get; set; }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class JsonExporter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) }
    };

    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        int overallScore,
        string grade,
        int ransomwareScore,
        string ransomwareGrade,
        ScanProfileType scanProfile)
    {
        var report = new AuditReport
        {
            Tool = "Network Security Auditor",
            ToolVersion = "5.0.0",
            SchemaVersion = "1.0",
            Timestamp = DateTime.UtcNow.ToString("o"),
            Client = "",
            Auditor = "",
            ScanProfile = scanProfile.ToString(),
            Environment = new EnvironmentSection
            {
                ComputerName = env.ComputerName,
                OsCaption = env.OSCaption,
                OsVersion = env.OSVersion,
                OsBuild = env.OSBuild,
                IsServer = env.IsServer,
                IsDomainJoined = env.IsDomainJoined,
                DomainName = env.DomainName,
                JoinType = env.JoinType,
                AzureAdJoined = env.AzureADJoined,
                IntuneManaged = env.IntuneManaged
            },
            Score = new ScoreSection
            {
                Overall = overallScore,
                Grade = grade,
                RansomwareReadiness = ransomwareScore,
                RansomwareGrade = ransomwareGrade
            },
            Findings = checks.Select(c => new FindingEntry
            {
                Id = c.Id,
                Label = c.Label,
                Category = c.Category,
                Severity = c.Severity.ToString(),
                Status = c.Status.ToString(),
                Findings = c.Findings,
                Evidence = c.Evidence,
                Compliance = c.Compliance,
                Notes = c.Notes,
                RemediationAssignee = c.RemediationAssignee,
                RemediationDueDate = c.RemediationDueDate?.ToString("yyyy-MM-dd")
            }).ToArray(),
            ComplianceFrameworks = BuildComplianceSummary(checks)
        };

        return JsonSerializer.Serialize(report, SerializerOptions);
    }

    private static Dictionary<string, ComplianceFrameworkSummary> BuildComplianceSummary(
        IEnumerable<CheckItemViewModel> checks)
    {
        var assessed = checks.Where(c => c.Status is not (CheckStatus.NA or CheckStatus.NotAssessed)).ToList();
        var total = assessed.Count;
        var passing = assessed.Count(c => c.Status is CheckStatus.Pass or CheckStatus.Partial);

        var frameworks = new Dictionary<string, ComplianceFrameworkSummary>
        {
            ["NIST 800-171"] = new() { TotalControls = total, PassingControls = passing, Coverage = total > 0 ? Math.Round((double)passing / total * 100, 1) : 0 },
            ["CMMC L2"] = new() { TotalControls = total, PassingControls = passing, Coverage = total > 0 ? Math.Round((double)passing / total * 100, 1) : 0 },
            ["PCI DSS"] = new() { TotalControls = total, PassingControls = passing, Coverage = total > 0 ? Math.Round((double)passing / total * 100, 1) : 0 },
        };

        return frameworks;
    }

    private sealed class AuditReport
    {
        public string Tool { get; set; } = "";
        public string ToolVersion { get; set; } = "";
        public string SchemaVersion { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public string Client { get; set; } = "";
        public string Auditor { get; set; } = "";
        public string ScanProfile { get; set; } = "";
        public EnvironmentSection Environment { get; set; } = new();
        public ScoreSection Score { get; set; } = new();
        public FindingEntry[] Findings { get; set; } = [];
        public Dictionary<string, ComplianceFrameworkSummary> ComplianceFrameworks { get; set; } = [];
    }

    private sealed class EnvironmentSection
    {
        public string ComputerName { get; set; } = "";
        public string OsCaption { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public int OsBuild { get; set; }
        public bool IsServer { get; set; }
        public bool IsDomainJoined { get; set; }
        public string DomainName { get; set; } = "";
        public string JoinType { get; set; } = "";
        public bool AzureAdJoined { get; set; }
        public bool IntuneManaged { get; set; }
    }

    private sealed class ScoreSection
    {
        public int Overall { get; set; }
        public string Grade { get; set; } = "";
        public int RansomwareReadiness { get; set; }
        public string RansomwareGrade { get; set; } = "";
    }

    private sealed class FindingEntry
    {
        public string Id { get; set; } = "";
        public string Label { get; set; } = "";
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Status { get; set; } = "";
        public string Findings { get; set; } = "";
        public string Evidence { get; set; } = "";
        public string Compliance { get; set; } = "";
        public string Notes { get; set; } = "";
        public string RemediationAssignee { get; set; } = "";
        public string? RemediationDueDate { get; set; }
    }

    private sealed class ComplianceFrameworkSummary
    {
        public int TotalControls { get; set; }
        public int PassingControls { get; set; }
        public double Coverage { get; set; }
    }
}

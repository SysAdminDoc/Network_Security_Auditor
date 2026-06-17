using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
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
        ScanProfileType scanProfile,
        int domainMaturityScore = 0,
        string domainMaturityGrade = "N/A")
    {
        var checkList = checks.ToList();
        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);

        var report = new AuditReport
        {
            Tool = "Network Security Auditor",
            ToolVersion = "5.0.0",
            SchemaVersion = "2.0",
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
            Score = BuildScoreSection(checkList, overallScore, grade, ransomwareScore, ransomwareGrade, domainMaturityScore, domainMaturityGrade),
            Findings = checkList.Select(c =>
            {
                var mapping = FrameworkMappings.All.GetValueOrDefault(c.Id);
                var mitre = MitreMappings.All.GetValueOrDefault(c.Id);
                var defend = D3FendMappings.All.GetValueOrDefault(c.Id);

                return new FindingEntry
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
                    RemediationDueDate = c.RemediationDueDate?.ToString("yyyy-MM-dd"),
                    RemediationUrl = c.RemediationUrl,
                    EvidenceMode = c.EvidenceMode.ToString(),
                    MitreTactics = mitre?.Tactics,
                    MitreTechniques = mitre?.Techniques,
                    MitreDescription = mitre?.Description,
                    D3FendStages = defend?.Stages,
                    D3FendTechniques = defend?.Techniques,
                    D3FendLabels = defend?.Labels,
                    D3FendDescription = defend?.Description,
                    FrameworkControls = mapping is not null ? new FrameworkControlIds
                    {
                        Cis = mapping.CIS,
                        Nist = mapping.NIST,
                        Cmmc = mapping.CMMC,
                        Hipaa = mapping.HIPAA,
                        Pci = mapping.PCI,
                        Soc2 = mapping.SOC2,
                        Iso27001 = mapping.ISO27001,
                        Stig = mapping.STIG,
                        FedRamp = mapping.FedRAMP,
                        E8 = mapping.E8,
                        CyberEssentials = mapping.CyberEssentials
                    } : null
                };
            }).ToArray(),
            ComplianceFrameworks = BuildComplianceSummary(statusLookup)
        };

        return JsonSerializer.Serialize(report, SerializerOptions);
    }

    private static ScoreSection BuildScoreSection(
        List<CheckItemViewModel> checks,
        int overallScore, string grade,
        int ransomwareScore, string ransomwareGrade,
        int domainMaturityScore, string domainMaturityGrade)
    {
        var (sprs, sprsConfidence) = Scoring.SprsScoreEngine.Calculate(checks);
        return new ScoreSection
        {
            Overall = overallScore,
            Grade = grade,
            RansomwareReadiness = ransomwareScore,
            RansomwareGrade = ransomwareGrade,
            DomainMaturity = domainMaturityScore,
            DomainMaturityGrade = domainMaturityGrade,
            SprsScore = sprs,
            SprsConfidence = sprsConfidence
        };
    }

    private static Dictionary<string, ComplianceFrameworkSummary> BuildComplianceSummary(
        Dictionary<string, CheckStatus> statusLookup)
    {
        var result = new Dictionary<string, ComplianceFrameworkSummary>();

        foreach (var (name, selector) in FrameworkDefinitions.All)
        {
            var mappedChecks = FrameworkMappings.All
                .Where(kv => selector(kv.Value) is not null)
                .Select(kv => kv.Key)
                .ToList();

            int total = 0, passing = 0;
            foreach (var checkId in mappedChecks)
            {
                if (!statusLookup.TryGetValue(checkId, out var status)) continue;
                if (status is CheckStatus.NA or CheckStatus.NotAssessed) continue;
                total++;
                if (status is CheckStatus.Pass or CheckStatus.Partial)
                    passing++;
            }

            result[name] = new ComplianceFrameworkSummary
            {
                TotalControls = total,
                PassingControls = passing,
                Coverage = total > 0 ? Math.Round((double)passing / total * 100, 1) : 0
            };
        }

        return result;
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
        public int DomainMaturity { get; set; }
        public string DomainMaturityGrade { get; set; } = "";
        public int SprsScore { get; set; }
        public string SprsConfidence { get; set; } = "";
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
        public string? RemediationUrl { get; set; }
        public string? EvidenceMode { get; set; }
        public string[]? MitreTactics { get; set; }
        public string[]? MitreTechniques { get; set; }
        public string? MitreDescription { get; set; }
        public string[]? D3FendStages { get; set; }
        public string[]? D3FendTechniques { get; set; }
        public string[]? D3FendLabels { get; set; }
        public string? D3FendDescription { get; set; }
        public FrameworkControlIds? FrameworkControls { get; set; }
    }

    private sealed class FrameworkControlIds
    {
        public string? Cis { get; set; }
        public string? Nist { get; set; }
        public string? Cmmc { get; set; }
        public string? Hipaa { get; set; }
        public string? Pci { get; set; }
        public string? Soc2 { get; set; }
        public string? Iso27001 { get; set; }
        public string? Stig { get; set; }
        public string? FedRamp { get; set; }
        public string? E8 { get; set; }
        public string? CyberEssentials { get; set; }
    }

    private sealed class ComplianceFrameworkSummary
    {
        public int TotalControls { get; set; }
        public int PassingControls { get; set; }
        public double Coverage { get; set; }
    }
}

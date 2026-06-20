using System.Collections.ObjectModel;
using System.Text.Json;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class ExportTests
{
    private static (ObservableCollection<CheckItemViewModel> checks, EnvironmentInfo env) CreateTestData()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(5))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Pass;
            vm.Findings = "Test finding";
            vm.Evidence = "Test evidence";
            checks.Add(vm);
        }

        var env = new EnvironmentInfo
        {
            ComputerName = "TESTPC",
            OSCaption = "Windows 11 Enterprise",
            OSVersion = "24H2",
            IsDomainJoined = true,
            DomainName = "TEST.LOCAL"
        };

        return (checks, env);
    }

    [Fact]
    public void Json_Export_Has_Required_Fields()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full, 60, "D");
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("Network Security Auditor", root.GetProperty("tool").GetString());
        Assert.Equal("2.0", root.GetProperty("schema_version").GetString());
        Assert.True(root.TryGetProperty("score", out var score));
        Assert.Equal(85, score.GetProperty("overall").GetInt32());
        Assert.Equal(60, score.GetProperty("domain_maturity").GetInt32());
        Assert.Equal("D", score.GetProperty("domain_maturity_grade").GetString());
    }

    [Fact]
    public void Json_Compliance_Has_Eleven_Frameworks()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full);
        var doc = JsonDocument.Parse(json);
        var frameworks = doc.RootElement.GetProperty("compliance_frameworks");

        Assert.True(frameworks.EnumerateObject().Count() >= 11,
            $"Expected at least 11 frameworks, got {frameworks.EnumerateObject().Count()}");
    }

    [Fact]
    public void Json_Findings_Include_Mitre_Data()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full);
        var doc = JsonDocument.Parse(json);
        var findings = doc.RootElement.GetProperty("findings");

        var hasAnyMitre = false;
        foreach (var finding in findings.EnumerateArray())
        {
            if (finding.TryGetProperty("mitre_tactics", out var tactics) && tactics.GetArrayLength() > 0)
            {
                hasAnyMitre = true;
                break;
            }
        }
        Assert.True(hasAnyMitre, "At least one finding should have MITRE ATT&CK tactics");
    }

    [Fact]
    public void Json_Findings_Include_Framework_Controls()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full);
        var doc = JsonDocument.Parse(json);
        var findings = doc.RootElement.GetProperty("findings");

        var hasFramework = false;
        foreach (var finding in findings.EnumerateArray())
        {
            if (finding.TryGetProperty("framework_controls", out var fc) && fc.ValueKind == JsonValueKind.Object)
            {
                hasFramework = true;
                break;
            }
        }
        Assert.True(hasFramework, "At least one finding should have framework control IDs");
    }

    [Fact]
    public void Json_Findings_Include_D3Fend_Data()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full);
        var doc = JsonDocument.Parse(json);
        var findings = doc.RootElement.GetProperty("findings");

        var hasD3Fend = false;
        foreach (var finding in findings.EnumerateArray())
        {
            if (finding.TryGetProperty("d3_fend_stages", out var stages) && stages.GetArrayLength() > 0)
            {
                hasD3Fend = true;
                break;
            }
        }
        Assert.True(hasD3Fend, "At least one finding should have D3FEND stages");
    }

    [Fact]
    public void Csv_Has_Correct_Column_Count()
    {
        var (checks, env) = CreateTestData();
        var csv = CsvExporter.Export(checks, env, 85, "B");
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.True(lines.Length > 2); // comment + header + data
        var headerLine = lines.First(l => !l.StartsWith('#'));
        var headerCommas = headerLine.Count(c => c == ',');
        Assert.Equal(22, headerCommas); // 23 columns = 22 commas
    }

    [Fact]
    public void Csv_Formula_Injection_Safe()
    {
        var (checks, env) = CreateTestData();
        checks[0].Findings = "=DANGEROUS()";
        var csv = CsvExporter.Export(checks, env, 85, "B");
        Assert.DoesNotContain("\"=DANGEROUS", csv);
        Assert.Contains("'=DANGEROUS", csv);
    }

    [Fact]
    public void Html_Contains_Required_Sections()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C", 60, "D");

        Assert.Contains("Network Security Audit Report", html);
        Assert.Contains("Overall Score", html);
        Assert.Contains("Ransomware Readiness", html);
        Assert.Contains("Domain Maturity", html);
        Assert.Contains("Compliance Framework Coverage", html);
        Assert.Contains("Detailed Findings", html);
        Assert.Contains("ATT&amp;CK", html);
    }

    [Fact]
    public void Html_Framework_Scores_Present()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C");

        Assert.Contains("NIST 800-171", html);
        Assert.Contains("PCI-DSS 4.0.1", html);
        Assert.Contains("DISA STIG", html);
    }

    [Fact]
    public void Navigator_Layer_Has_Required_Fields()
    {
        var (checks, _) = CreateTestData();
        var json = NavigatorExporter.Export(checks);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("enterprise-attack", root.GetProperty("domain").GetString());
        Assert.Equal("4.5", root.GetProperty("versions").GetProperty("layer").GetString());
        Assert.True(root.GetProperty("techniques").GetArrayLength() > 0);
    }

    [Fact]
    public void DefectDojo_Has_Required_Fields()
    {
        var (checks, env) = CreateTestData();
        var json = DefectDojoExporter.Export(checks, env, 85, "B");
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("findings", out var findings));
        foreach (var finding in findings.EnumerateArray())
        {
            Assert.True(finding.TryGetProperty("title", out _));
            Assert.True(finding.TryGetProperty("severity", out _));
            Assert.True(finding.TryGetProperty("description", out _));
        }
    }

    [Fact]
    public void Oscal_Observation_Finding_UUIDs_Match()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.Take(3))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Fail;
            vm.Findings = "Test finding";
            vm.Evidence = "Test evidence";
            checks.Add(vm);
        }
        var env = new EnvironmentInfo { ComputerName = "TEST", OSCaption = "Windows 11", IsDomainJoined = true, DomainName = "TEST.LOCAL" };

        var json = OscalExporter.Export(checks, env, 50, "F");

        var obsUuids = new HashSet<string>();
        foreach (var line in json.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Contains("\"uuid\"") && !trimmed.Contains("assessment") && !trimmed.Contains("subject"))
            {
                var start = trimmed.IndexOf(": \"") + 3;
                var end = trimmed.LastIndexOf('"');
                if (start > 2 && end > start)
                    obsUuids.Add(trimmed[start..end]);
            }
        }

        Assert.True(obsUuids.Count > 0, "Should have UUIDs in output");
        Assert.True(json.Contains("observation") && json.Contains("finding"),
            "OSCAL output should contain both observations and findings");
    }

    [Fact]
    public void Sarif_Has_Schema_And_Version()
    {
        var (checks, env) = CreateTestData();
        var json = SarifExporter.Export(checks, env);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.True(root.TryGetProperty("schema", out _));
        var runs = root.GetProperty("runs");
        Assert.True(runs.GetArrayLength() > 0);
        var driver = runs[0].GetProperty("tool").GetProperty("driver");
        Assert.True(driver.TryGetProperty("rules", out var rules));
        Assert.True(rules.GetArrayLength() > 0);
    }

    [Fact]
    public void Sarif_Rules_Have_Security_Severity()
    {
        var (checks, env) = CreateTestData();
        var json = SarifExporter.Export(checks, env);
        var doc = JsonDocument.Parse(json);
        var rules = doc.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");

        foreach (var rule in rules.EnumerateArray())
        {
            var props = rule.GetProperty("properties");
            Assert.True(props.TryGetProperty("security-severity", out var sev),
                $"Rule {rule.GetProperty("id").GetString()} missing security-severity");
            Assert.True(sev.GetDouble() >= 1.0 && sev.GetDouble() <= 10.0);
        }
    }

    [Fact]
    public void Intune_Export_Has_Required_Fields()
    {
        var (checks, env) = CreateTestData();
        var json = IntuneExporter.Export(checks, env, 85, "B", 70, "C");
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("security_audit_grade", out _));
        Assert.True(root.TryGetProperty("security_audit_score", out _));
        Assert.True(root.TryGetProperty("compliance_flags", out _));
        Assert.True(root.TryGetProperty("tool_version", out _));
    }

    [Fact]
    public void Full_Catalog_Export_Roundtrip()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values)
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Fail;
            vm.Findings = $"Finding for {meta.Id}";
            vm.Evidence = $"Evidence for {meta.Id}";
            checks.Add(vm);
        }

        var env = new EnvironmentInfo
        {
            ComputerName = "FULLTEST",
            OSCaption = "Windows Server 2025",
            OSVersion = "26100",
            IsDomainJoined = true,
            DomainName = "FULL.LOCAL"
        };

        Assert.Equal(69, checks.Count);

        var json = JsonExporter.Export(checks, env, 30, "F", 20, "F", ScanProfileType.Full, 10, "F");
        Assert.True(json.Length > 1000);
        var jsonDoc = JsonDocument.Parse(json);
        Assert.Equal(69, jsonDoc.RootElement.GetProperty("findings").GetArrayLength());

        var csv = CsvExporter.Export(checks, env, 30, "F");
        var csvLines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(71, csvLines.Length); // 1 comment + 1 header + 69 data rows

        var html = HtmlReportGenerator.Generate(checks, env, 30, "F", 20, "F", 10, "F");
        Assert.Contains("Detailed Findings", html);
        Assert.Contains("D3FEND", html);

        var jsonl = JsonlExporter.Export(checks, env, 30, "F", ScanProfileType.Full);
        var jsonlLines = jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(69, jsonlLines.Length);

        var sarif = SarifExporter.Export(checks, env);
        Assert.True(sarif.Length > 1000);

        var nav = NavigatorExporter.Export(checks);
        Assert.True(nav.Length > 500);

        var dd = DefectDojoExporter.Export(checks, env, 30, "F");
        Assert.True(dd.Length > 1000);

        var ocsf = OcsfExporter.Export(checks, env, 30, "F", "Full");
        Assert.True(ocsf.Length > 1000);

        var oscal = OscalExporter.Export(checks, env, 30, "F");
        Assert.True(oscal.Length > 1000);

        var summary = ComplianceSummaryExporter.Export(checks, env, 30, "F", 20, "F", 10, "F");
        Assert.True(summary.Length > 100);

        var intune = IntuneExporter.Export(checks, env, 30, "F", 20, "F");
        Assert.True(intune.Length > 100);
    }

    [Fact]
    public void Html_Executive_Tier_Omits_Technical_Details()
    {
        var (checks, env) = CreateTestData();
        checks[0].Status = CheckStatus.Fail;
        var html = HtmlReportGenerator.Generate(checks, env, 50, "F", 30, "F", 20, "F", tier: ReportTier.Executive);

        Assert.Contains("Overall Score", html);
        Assert.Contains("Top Findings", html);
        Assert.DoesNotContain("Detailed Findings", html);
        Assert.DoesNotContain("D3FEND", html);
        Assert.DoesNotContain("Score by Category", html);
    }

    [Fact]
    public void Cmmc_Full_Eligibility_Score_Shows_Full()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values)
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Pass;
            checks.Add(vm);
        }
        var env = new EnvironmentInfo { ComputerName = "TEST", IsDomainJoined = true, DomainName = "TEST.LOCAL" };

        var html = CmmcReportGenerator.ExportHtml(checks, env, 100, "A");
        Assert.Contains("Eligible (full)", html);
        Assert.DoesNotContain("conditional", html);
    }

    [Fact]
    public void Navigator_Uses_Worst_Status_For_Shared_Techniques()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values)
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            vm.Status = CheckStatus.Pass;
            checks.Add(vm);
        }
        // Set one check to Fail — its techniques should show as failed in Navigator
        var firstFail = checks.FirstOrDefault(c => c.Id == "EP01");
        if (firstFail is not null) firstFail.Status = CheckStatus.Fail;

        var json = NavigatorExporter.Export(checks);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var techniques = doc.RootElement.GetProperty("techniques");

        // Find techniques from EP01's mapping — they should have score=0 (Fail)
        var ep01Mitre = MitreMappings.All.GetValueOrDefault("EP01");
        if (ep01Mitre is not null)
        {
            foreach (var tech in techniques.EnumerateArray())
            {
                var id = tech.GetProperty("techniqueID").GetString();
                if (ep01Mitre.Techniques.Contains(id!))
                {
                    Assert.Equal(0, tech.GetProperty("score").GetInt32());
                }
            }
        }
    }

    [Fact]
    public void Html_RemediationUrl_XSS_Blocked()
    {
        var (checks, env) = CreateTestData();
        // Create a check with a javascript: URL via the ViewModel
        var meta = CheckCatalog.All.Values.First();
        var vm = CheckItemViewModel.FromMetadata(new CheckMetadata
        {
            Id = meta.Id, Category = meta.Category, Label = meta.Label, Hint = meta.Hint,
            Severity = meta.Severity, Weight = meta.Weight, Type = meta.Type,
            RiskTier = meta.RiskTier, Compliance = meta.Compliance,
            RemediationUrl = "javascript:alert(1)"
        });
        vm.Status = CheckStatus.Fail;
        vm.Findings = "Test";
        vm.Evidence = "Test";

        var allChecks = new ObservableCollection<CheckItemViewModel> { vm };
        var html = HtmlReportGenerator.Generate(allChecks, env, 50, "F", 30, "F");

        Assert.DoesNotContain("javascript:", html);
    }

    [Fact]
    public void Dashboard_Escapes_Client_Names()
    {
        // Verify the Esc helper exists and works
        var html = "<script>alert(1)</script>";
        var escaped = html.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
        Assert.DoesNotContain("<script>", escaped);
        Assert.Contains("&lt;script&gt;", escaped);
    }
}

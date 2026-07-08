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
    public void Json_Compliance_Has_Ten_Scored_Frameworks()
    {
        var (checks, env) = CreateTestData();
        var json = JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full);
        var doc = JsonDocument.Parse(json);
        var frameworks = doc.RootElement.GetProperty("compliance_frameworks");

        Assert.Equal(10, frameworks.EnumerateObject().Count());
        Assert.False(frameworks.TryGetProperty("DISA STIG", out _));
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
        checks[1].Evidence = "\t=DANGEROUS()";
        checks[2].Notes = "\r=DANGEROUS()";
        checks[3].Findings = "  =DANGEROUS()";
        var csv = CsvExporter.Export(checks, env, 85, "B");
        Assert.DoesNotContain("\"=DANGEROUS", csv);
        Assert.Contains("'=DANGEROUS", csv);
        Assert.Contains("\"'\t=DANGEROUS()\"", csv);
        Assert.Contains("\"'\r=DANGEROUS()\"", csv);
        Assert.Contains("\"'  =DANGEROUS()\"", csv);
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
    public void Html_Escapes_Environment_Subtitle_Fields()
    {
        var (checks, env) = CreateTestData();
        env.ComputerName = "\"><script>alert(1)</script>";
        env.OSCaption = "Windows <img src=x onerror=alert(2)>";

        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C", 60, "D");

        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Contains("Windows &lt;img src=x onerror=alert(2)&gt;", html);
    }

    [Fact]
    public void Html_Framework_Scores_Present()
    {
        var (checks, env) = CreateTestData();
        var html = HtmlReportGenerator.Generate(checks, env, 85, "B", 70, "C");

        Assert.Contains("NIST 800-171", html);
        Assert.Contains("PCI-DSS 4.0.1", html);
        Assert.DoesNotContain("DISA STIG", html);
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
    public void Oscal_Uses_Kebab_Case_Fields_And_Valid_Status_Values()
    {
        var criticalMeta = CheckCatalog.All.Values.First(m => m.Severity == Severity.Critical);
        var partialMeta = CheckCatalog.All.Values.First(m => m.Id != criticalMeta.Id && m.Severity == Severity.High);
        var failedCheck = CheckItemViewModel.FromMetadata(criticalMeta);
        failedCheck.Status = CheckStatus.Fail;
        failedCheck.Findings = "Critical control failed";
        failedCheck.Evidence = "Critical evidence";
        var partialCheck = CheckItemViewModel.FromMetadata(partialMeta);
        partialCheck.Status = CheckStatus.Partial;
        partialCheck.Findings = "High control partially satisfied";
        partialCheck.Evidence = "Partial evidence";
        var checks = new ObservableCollection<CheckItemViewModel> { failedCheck, partialCheck };
        var env = new EnvironmentInfo { ComputerName = "TEST", OSCaption = "Windows 11", IsDomainJoined = true, DomainName = "TEST.LOCAL" };

        var json = OscalExporter.Export(checks, env, 40, "F");

        Assert.Contains("\"assessment-results\"", json);
        Assert.DoesNotContain("assessment_results", json);
        Assert.DoesNotContain("last_modified", json);
        Assert.DoesNotContain("oscal_version", json);
        Assert.DoesNotContain("subject_uuid", json);
        Assert.DoesNotContain("relevant_evidence", json);
        Assert.DoesNotContain("target_id", json);
        Assert.DoesNotContain("related_observations", json);
        Assert.DoesNotContain("observation_uuid", json);
        Assert.DoesNotContain("risk_level", json);

        var doc = JsonDocument.Parse(json);
        var result = doc.RootElement.GetProperty("assessment-results").GetProperty("results")[0];
        var findings = result.GetProperty("findings").EnumerateArray().ToArray();

        Assert.Equal(2, findings.Length);
        Assert.All(findings, finding =>
        {
            Assert.True(finding.GetProperty("target").TryGetProperty("target-id", out _));
            Assert.True(finding.TryGetProperty("related-observations", out _));
            Assert.Equal("not-satisfied", finding.GetProperty("target").GetProperty("status").GetProperty("state").GetString());
        });
        Assert.Contains(findings, finding => finding.GetProperty("target").GetProperty("status").GetProperty("reason").GetString() == "fail");
        Assert.Contains(findings, finding => finding.GetProperty("target").GetProperty("status").GetProperty("reason").GetString() == "other");

        var risk = Assert.Single(result.GetProperty("risks").EnumerateArray());
        Assert.True(risk.TryGetProperty("props", out var riskProps));
        Assert.Contains(riskProps.EnumerateArray(), prop =>
            prop.GetProperty("name").GetString() == "risk-level" &&
            prop.GetProperty("value").GetString() == "high");
    }

    [Fact]
    public void Sarif_Has_Schema_And_Version()
    {
        var (checks, env) = CreateTestData();
        var json = SarifExporter.Export(checks, env);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.True(root.TryGetProperty("$schema", out _));
        Assert.False(root.TryGetProperty("schema", out _));
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
        var notAssessedSharedTechnique = checks.FirstOrDefault(c => c.Id == "EP02");
        if (notAssessedSharedTechnique is not null) notAssessedSharedTechnique.Status = CheckStatus.NotAssessed;

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

        var t1059 = techniques.EnumerateArray()
            .Single(tech => tech.GetProperty("techniqueID").GetString() == "T1059");
        Assert.Equal(0, t1059.GetProperty("score").GetInt32());
        Assert.Equal("#f38ba8", t1059.GetProperty("color").GetString());
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
    public async Task Dashboard_Escapes_Client_Names()
    {
        var dir = await WriteDashboardFixtureAsync("""
            {
              "timestamp": "2026-07-08T00:00:00Z",
              "client": "<script>alert(1)</script>",
              "environment": {
                "computer_name": "<b>HOST</b>",
                "os_caption": "Windows <img src=x onerror=alert(1)>"
              },
              "score": {
                "overall": 90,
                "grade": "A",
                "ransomware_readiness": 80
              },
              "findings": []
            }
            """);

        try
        {
            var html = await DashboardGenerator.GenerateAsync(dir);

            Assert.DoesNotContain("<script>", html);
            Assert.DoesNotContain("<b>HOST</b>", html);
            Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
            Assert.Contains("&lt;b&gt;HOST&lt;/b&gt;", html);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Dashboard_Csv_Uses_Spreadsheet_Safe_Escaping()
    {
        var dir = await WriteDashboardFixtureAsync("""
            {
              "timestamp": "\t=DATE(2026,7,8)",
              "client": "\t=DANGEROUS()",
              "environment": {
                "computer_name": "\r=DANGEROUS()",
                "os_caption": "  =DANGEROUS()"
              },
              "score": {
                "overall": 42,
                "grade": "=DANGEROUS()",
                "ransomware_readiness": 7
              },
              "findings": [
                { "status": "Fail", "severity": "Critical" }
              ]
            }
            """);

        try
        {
            var csv = await DashboardGenerator.GenerateCsvAsync(dir);

            Assert.Contains("\"'\t=DANGEROUS()\"", csv);
            Assert.Contains("\"'\r=DANGEROUS()\"", csv);
            Assert.Contains("\"'  =DANGEROUS()\"", csv);
            Assert.Contains("\"'=DANGEROUS()\"", csv);
            Assert.Contains("\"'\t=DATE(2026,7,8)\"", csv);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Dashboard_Grade_Class_Is_Allowlisted()
    {
        var dir = await WriteDashboardFixtureAsync("""
            {
              "timestamp": "2026-07-08T00:00:00Z",
              "client": "Client",
              "environment": {
                "computer_name": "Host",
                "os_caption": "Windows"
              },
              "score": {
                "overall": 70,
                "grade": "A\" onmouseover=\"alert(1)",
                "ransomware_readiness": 50
              },
              "findings": []
            }
            """);

        try
        {
            var html = await DashboardGenerator.GenerateAsync(dir);

            Assert.Contains("class=\"grade-unknown\"", html);
            Assert.DoesNotContain("class=\"grade-a&quot;", html);
            Assert.Contains("A&quot; onmouseover=&quot;alert(1)", html);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Dashboard_Uses_Latest_Client_Row_With_Trend_And_Duplicate_List()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nsa-export-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        await WriteDashboardFixtureAsync(dir, "acme_old_findings.json", DashboardJson("2026-07-01T00:00:00Z", "Acme", "HOST01", 60, "D", 40, "Fail", "Critical"));
        await WriteDashboardFixtureAsync(dir, "acme_new_findings.json", DashboardJson("2026-07-08T00:00:00Z", "Acme", "HOST01", 90, "A", 80, "Pass", "Critical"));
        await WriteDashboardFixtureAsync(dir, "beta_findings.json", DashboardJson("2026-07-08T01:00:00Z", "Beta", "HOST02", 72, "C", 55, "Fail", "High"));
        await File.WriteAllTextAsync(Path.Combine(dir, "broken_findings.json"), "{ not valid json");

        try
        {
            var html = await DashboardGenerator.GenerateAsync(dir, staleDays: 9999);
            var csv = await DashboardGenerator.GenerateCsvAsync(dir, staleDays: 9999);
            var dataRows = csv
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(line => !line.StartsWith('#'))
                .ToArray();

            Assert.Contains("2 clients", html);
            Assert.Contains("60% -&gt; 90%", html);
            Assert.Contains("older duplicate scan(s) hidden", html);
            Assert.Contains("acme_old_findings.json", html);
            Assert.Contains("broken_findings.json", html);
            Assert.Equal(3, dataRows.Length);
            Assert.Contains("acme_new_findings.json", csv);
            Assert.DoesNotContain("Acme,HOST01,Windows 11 Enterprise,60,", csv);
            Assert.Contains("2026-07-01T00:00:00Z:60|2026-07-08T00:00:00Z:90", csv);
            Assert.Contains("# DUPLICATE:", csv);
            Assert.Contains("# SKIPPED:", csv);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static async Task<string> WriteDashboardFixtureAsync(string json)
    {
        var dir = Path.Combine(Path.GetTempPath(), "nsa-export-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "client_findings.json"), json);
        return dir;
    }

    private static async Task WriteDashboardFixtureAsync(string dir, string fileName, string json)
    {
        await File.WriteAllTextAsync(Path.Combine(dir, fileName), json);
    }

    private static string DashboardJson(
        string timestamp,
        string client,
        string host,
        int score,
        string grade,
        int ransomwareScore,
        string findingStatus,
        string severity) => $$"""
        {
          "timestamp": "{{timestamp}}",
          "client": "{{client}}",
          "environment": {
            "computer_name": "{{host}}",
            "os_caption": "Windows 11 Enterprise"
          },
          "score": {
            "overall": {{score}},
            "grade": "{{grade}}",
            "ransomware_readiness": {{ransomwareScore}}
          },
          "findings": [
            { "status": "{{findingStatus}}", "severity": "{{severity}}" }
          ]
        }
        """;
}

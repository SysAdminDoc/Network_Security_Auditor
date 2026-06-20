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

        Assert.True(lines.Length > 1);
        var headerCommas = lines[0].Count(c => c == ',');
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
}

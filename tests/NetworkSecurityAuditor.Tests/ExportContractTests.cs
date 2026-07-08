using System.Collections.ObjectModel;
using System.Text.Json;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class ExportContractTests
{
    public static IEnumerable<object[]> GoldenContracts()
    {
        yield return ["findings.schema.json", "findings.golden.json"];
        yield return ["jsonl-event.schema.json", "jsonl-event.golden.json"];
        yield return ["intune.schema.json", "intune.golden.json"];
        yield return ["compliance-summary.schema.json", "compliance-summary.golden.json"];
        yield return ["ocsf-compliance-finding.schema.json", "ocsf-compliance-finding.golden.json"];
        yield return ["oscal-assessment-results.schema.json", "oscal-assessment-results.golden.json"];
        yield return ["dashboard-client-row.schema.json", "dashboard-client-row.golden.json"];
        yield return ["siem-field-mapping.schema.json", "siem-field-mapping.golden.json"];
    }

    [Fact]
    public void Export_Schema_Files_Are_Parseable_Contracts()
    {
        foreach (var schemaFile in Directory.GetFiles(SchemaDir(), "*.schema.json").OrderBy(Path.GetFileName))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(schemaFile));
            var root = doc.RootElement;

            Assert.True(root.TryGetProperty("$schema", out _), $"{schemaFile} is missing $schema.");
            Assert.True(root.TryGetProperty("$id", out _), $"{schemaFile} is missing $id.");
            Assert.Equal("object", root.GetProperty("type").GetString());
            Assert.True(root.GetProperty("required").GetArrayLength() > 0, $"{schemaFile} has no required contract fields.");
        }
    }

    [Theory]
    [MemberData(nameof(GoldenContracts))]
    public void Golden_Export_Fixtures_Conform_To_Committed_Schemas(string schemaFile, string fixtureFile)
    {
        ValidateJsonDocument(schemaFile, File.ReadAllText(FixturePath(fixtureFile)));
    }

    [Fact]
    public void Generated_Exports_Conform_To_Committed_Schemas()
    {
        var (checks, env) = CreateContractData();

        ValidateJsonDocument(
            "findings.schema.json",
            JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full, 60, "D", "Example Client", "Example Auditor"));
        ValidateJsonDocument(
            "jsonl-event.schema.json",
            FirstJsonlEvent(JsonlExporter.Export(checks, env, 85, "B", ScanProfileType.Full)));
        ValidateJsonDocument(
            "intune.schema.json",
            IntuneExporter.Export(checks, env, 85, "B", 70, "C"));
        ValidateJsonDocument(
            "compliance-summary.schema.json",
            ComplianceSummaryExporter.Export(checks, env, 85, "B", 70, "C", 60, "D"));
        ValidateJsonDocument(
            "ocsf-compliance-finding.schema.json",
            FirstJsonlEvent(OcsfExporter.Export(checks, env, 85, "B", "Full")));
        ValidateJsonDocument(
            "oscal-assessment-results.schema.json",
            OscalExporter.Export(checks, env, 85, "B"));

        var siemDir = Path.Combine(Path.GetTempPath(), "nsa-siem-contract-" + Guid.NewGuid().ToString("N"));
        try
        {
            SiemContentPackExporter.ExportAll(siemDir);
            ValidateJsonDocument(
                "siem-field-mapping.schema.json",
                File.ReadAllText(Path.Combine(siemDir, "field_mapping.json")));
        }
        finally
        {
            if (Directory.Exists(siemDir))
                Directory.Delete(siemDir, recursive: true);
        }
    }

    private static (ObservableCollection<CheckItemViewModel> checks, EnvironmentInfo env) CreateContractData()
    {
        var checks = new ObservableCollection<CheckItemViewModel>();
        var metas = new[]
        {
            CheckCatalog.All.Values.First(m => m.Severity == Severity.Critical),
            CheckCatalog.All.Values.First(m => m.Severity == Severity.High),
            CheckCatalog.All.Values.First(m => m.Severity == Severity.Medium)
        };
        var statuses = new[] { CheckStatus.Fail, CheckStatus.Pass, CheckStatus.Partial };

        for (var i = 0; i < metas.Length; i++)
        {
            var check = CheckItemViewModel.FromMetadata(metas[i]);
            check.Status = statuses[i];
            check.Findings = $"Contract finding for {check.Id}";
            check.Evidence = $"Contract evidence for {check.Id}";
            check.DurationMs = 12.3 + i;
            checks.Add(check);
        }

        return (checks, new EnvironmentInfo
        {
            ComputerName = "HOST01",
            OSCaption = "Windows 11 Enterprise",
            OSVersion = "24H2",
            OSBuild = 26100,
            IsDomainJoined = true,
            DomainName = "EXAMPLE.LOCAL",
            JoinType = "Domain",
            IntuneManaged = true
        });
    }

    private static void ValidateJsonDocument(string schemaFile, string json)
    {
        using var schema = JsonDocument.Parse(File.ReadAllText(SchemaPath(schemaFile)));
        using var document = JsonDocument.Parse(json);
        Validate(schema.RootElement, document.RootElement, "$");
    }

    private static void Validate(JsonElement schema, JsonElement instance, string path)
    {
        if (schema.TryGetProperty("type", out var type))
        {
            Assert.True(MatchesType(instance, type), $"{path} expected type {type} but found {instance.ValueKind}.");
        }

        if (schema.TryGetProperty("enum", out var enumValues))
        {
            Assert.Contains(enumValues.EnumerateArray(), value => JsonElement.DeepEquals(value, instance));
        }

        if (schema.TryGetProperty("required", out var required) && instance.ValueKind == JsonValueKind.Object)
        {
            foreach (var requiredName in required.EnumerateArray().Select(e => e.GetString()).Where(name => name is not null))
            {
                Assert.True(instance.TryGetProperty(requiredName!, out _), $"{path} is missing required property '{requiredName}'.");
            }
        }

        if (schema.TryGetProperty("properties", out var properties) && instance.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in properties.EnumerateObject())
            {
                if (instance.TryGetProperty(property.Name, out var child))
                    Validate(property.Value, child, $"{path}.{property.Name}");
            }
        }

        if (schema.TryGetProperty("items", out var items) && instance.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in instance.EnumerateArray())
            {
                Validate(items, item, $"{path}[{index}]");
                index++;
            }
        }
    }

    private static bool MatchesType(JsonElement instance, JsonElement type)
    {
        return type.ValueKind switch
        {
            JsonValueKind.String => MatchesTypeName(instance, type.GetString()),
            JsonValueKind.Array => type.EnumerateArray().Any(t => MatchesTypeName(instance, t.GetString())),
            _ => true
        };
    }

    private static bool MatchesTypeName(JsonElement instance, string? typeName) => typeName switch
    {
        "object" => instance.ValueKind == JsonValueKind.Object,
        "array" => instance.ValueKind == JsonValueKind.Array,
        "string" => instance.ValueKind == JsonValueKind.String,
        "integer" => instance.ValueKind == JsonValueKind.Number && instance.TryGetInt64(out _),
        "number" => instance.ValueKind == JsonValueKind.Number,
        "boolean" => instance.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "null" => instance.ValueKind == JsonValueKind.Null,
        _ => true
    };

    private static string FirstJsonlEvent(string jsonl)
    {
        return jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)[0];
    }

    private static string SchemaDir() => Path.Combine(FindRepoRoot(), "schemas", "exports");

    private static string SchemaPath(string fileName) => Path.Combine(SchemaDir(), fileName);

    private static string FixturePath(string fileName) => Path.Combine(FindRepoRoot(), "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Exports", fileName);

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}

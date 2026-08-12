using System.Collections.ObjectModel;
using System.Globalization;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        yield return ["oscal-poam.schema.json", "oscal-poam.golden.json"];
        yield return ["dashboard-client-row.schema.json", "dashboard-client-row.golden.json"];
        yield return ["dashboard-summary.schema.json", "dashboard-summary.golden.json"];
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
            AssertSupportedSchemaKeywords(root, schemaFile);
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
        ValidateJsonDocument(
            "oscal-poam.schema.json",
            OscalPoamExporter.Export(checks, env));

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

    [Fact]
    public async Task Generated_Dashboard_Conforms_To_Committed_Schema()
    {
        var (checks, env) = CreateContractData();
        var dir = Path.Combine(Path.GetTempPath(), "nsa-dashboard-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(dir, "example_findings.json"),
                JsonExporter.Export(checks, env, 85, "B", 70, "C", ScanProfileType.Full, 60, "D", "Example Client", "Example Auditor"));

            ValidateJsonDocument(
                "dashboard-summary.schema.json",
                await DashboardGenerator.GenerateJsonAsync(dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Export_Schema_Validation_Rejects_Missing_Required_And_Dynamic_Map_Type_Errors()
    {
        var node = JsonNode.Parse(File.ReadAllText(FixturePath("compliance-summary.golden.json")))!.AsObject();
        node.Remove("tool");
        var categoryScores = node["category_scores"]!.AsObject();
        var firstCategory = categoryScores.First().Value!.AsObject();
        firstCategory["pct"] = "not-a-number";

        var errors = GetValidationErrors(
            "compliance-summary.schema.json",
            node.ToJsonString());

        Assert.Contains(errors, error => error.Contains("missing required property 'tool'", StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains("$.category_scores.Endpoint Security.pct", StringComparison.Ordinal));
    }

    [Fact]
    public void Export_Schema_Validation_Enforces_References_Composition_And_Bounds()
    {
        using var schema = JsonDocument.Parse("""
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "$defs": {
            "positiveInteger": { "type": "integer", "minimum": 1 }
          },
          "type": "object",
          "required": ["id", "status", "value"],
          "properties": {
            "id": { "$ref": "#/$defs/positiveInteger" },
            "status": { "oneOf": [{ "const": "pass" }, { "const": "fail" }] },
            "value": {
              "allOf": [{ "type": "integer" }, { "minimum": 1 }],
              "anyOf": [{ "const": 2 }, { "const": 3 }]
            }
          }
        }
        """);

        using var validDocument = JsonDocument.Parse("{\"id\":1,\"status\":\"pass\",\"value\":2}");
        var valid = Validate(schema.RootElement, validDocument.RootElement, "$");
        Assert.Empty(valid);

        using var invalidDocument = JsonDocument.Parse("{\"id\":0,\"status\":\"unknown\",\"value\":4}");
        var invalid = Validate(schema.RootElement, invalidDocument.RootElement, "$");
        Assert.NotEmpty(invalid);
        Assert.Contains(invalid, error => error.Contains("$.id", StringComparison.Ordinal));
        Assert.Contains(invalid, error => error.Contains("$.status", StringComparison.Ordinal));
        Assert.Contains(invalid, error => error.Contains("$.value", StringComparison.Ordinal));
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

    private static IReadOnlyList<string> ValidateJsonDocument(string schemaFile, string json)
    {
        var errors = GetValidationErrors(schemaFile, json);
        Assert.True(errors.Count == 0, string.Join(Environment.NewLine, errors));
        return errors;
    }

    private static IReadOnlyList<string> GetValidationErrors(string schemaFile, string json)
    {
        using var schema = JsonDocument.Parse(File.ReadAllText(SchemaPath(schemaFile)));
        using var document = JsonDocument.Parse(json);
        return Validate(schema.RootElement, document.RootElement, "$");
    }

    private static IReadOnlyList<string> Validate(JsonElement schema, JsonElement instance, string path)
    {
        var errors = new List<string>();
        Validate(schema, instance, path, schema, errors, new HashSet<string>(StringComparer.Ordinal));
        return errors;
    }

    private static void Validate(
        JsonElement schema,
        JsonElement instance,
        string path,
        JsonElement rootSchema,
        ICollection<string> errors,
        ISet<string> activeReferences)
    {
        if (schema.TryGetProperty("$ref", out var reference))
        {
            var referenceText = reference.GetString();
            if (string.IsNullOrWhiteSpace(referenceText) || !referenceText.StartsWith("#", StringComparison.Ordinal))
            {
                errors.Add($"{path} has an unsupported external $ref '{referenceText}'.");
                return;
            }

            if (!activeReferences.Add(referenceText))
            {
                errors.Add($"{path} contains a recursive $ref cycle at '{referenceText}'.");
                return;
            }

            if (!TryResolveJsonPointer(rootSchema, referenceText[1..], out var referencedSchema))
            {
                errors.Add($"{path} references missing schema '{referenceText}'.");
            }
            else
            {
                Validate(referencedSchema, instance, path, rootSchema, errors, activeReferences);
            }

            activeReferences.Remove(referenceText);
        }

        if (schema.TryGetProperty("type", out var type))
        {
            if (!MatchesType(instance, type))
                errors.Add($"{path} expected type {type} but found {instance.ValueKind}.");
        }

        if (schema.TryGetProperty("enum", out var enumValues))
        {
            if (!enumValues.EnumerateArray().Any(value => JsonElement.DeepEquals(value, instance)))
                errors.Add($"{path} is not one of the values in enum.");
        }

        if (schema.TryGetProperty("const", out var constant) && !JsonElement.DeepEquals(constant, instance))
        {
            errors.Add($"{path} does not match const.");
        }

        ValidateComposition(schema, instance, path, rootSchema, errors, activeReferences);

        if (schema.TryGetProperty("required", out var required) && instance.ValueKind == JsonValueKind.Object)
        {
            foreach (var requiredName in required.EnumerateArray().Select(e => e.GetString()).Where(name => name is not null))
            {
                if (!instance.TryGetProperty(requiredName!, out _))
                    errors.Add($"{path} is missing required property '{requiredName}'.");
            }
        }

        if (schema.TryGetProperty("properties", out var properties) && instance.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in properties.EnumerateObject())
            {
                if (instance.TryGetProperty(property.Name, out var child))
                    Validate(property.Value, child, $"{path}.{property.Name}", rootSchema, errors, activeReferences);
            }
        }

        if (schema.TryGetProperty("additionalProperties", out var additionalProperties) && instance.ValueKind == JsonValueKind.Object)
        {
            var declared = schema.TryGetProperty("properties", out var declaredProperties)
                ? declaredProperties.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);

            foreach (var property in instance.EnumerateObject().Where(property => !declared.Contains(property.Name)))
            {
                if (additionalProperties.ValueKind == JsonValueKind.False)
                {
                    errors.Add($"{path} contains unexpected property '{property.Name}'.");
                }
                else if (additionalProperties.ValueKind == JsonValueKind.Object)
                {
                    Validate(additionalProperties, property.Value, $"{path}.{property.Name}", rootSchema, errors, activeReferences);
                }
            }
        }

        if (schema.TryGetProperty("items", out var items) && instance.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in instance.EnumerateArray())
            {
                Validate(items, item, $"{path}[{index}]", rootSchema, errors, activeReferences);
                index++;
            }
        }

        if (schema.TryGetProperty("prefixItems", out var prefixItems) && instance.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var itemSchema in prefixItems.EnumerateArray())
            {
                if (index >= instance.GetArrayLength())
                    break;

                Validate(itemSchema, instance[index], $"{path}[{index}]", rootSchema, errors, activeReferences);
                index++;
            }
        }

        ValidateScalarConstraints(schema, instance, path, errors);
    }

    private static void ValidateComposition(
        JsonElement schema,
        JsonElement instance,
        string path,
        JsonElement rootSchema,
        ICollection<string> errors,
        ISet<string> activeReferences)
    {
        ValidateAllOf(schema, instance, path, rootSchema, errors, activeReferences);
        ValidateAnyOf(schema, instance, path, rootSchema, errors, activeReferences, exactlyOne: false);
        ValidateAnyOf(schema, instance, path, rootSchema, errors, activeReferences, exactlyOne: true);

        if (schema.TryGetProperty("not", out var notSchema))
        {
            var notErrors = new List<string>();
            Validate(notSchema, instance, path, rootSchema, notErrors, new HashSet<string>(activeReferences, StringComparer.Ordinal));
            if (notErrors.Count == 0)
                errors.Add($"{path} matches a forbidden schema.");
        }
    }

    private static void ValidateAllOf(
        JsonElement schema,
        JsonElement instance,
        string path,
        JsonElement rootSchema,
        ICollection<string> errors,
        ISet<string> activeReferences)
    {
        if (!schema.TryGetProperty("allOf", out var allOf))
            return;

        foreach (var childSchema in allOf.EnumerateArray())
            Validate(childSchema, instance, path, rootSchema, errors, activeReferences);
    }

    private static void ValidateAnyOf(
        JsonElement schema,
        JsonElement instance,
        string path,
        JsonElement rootSchema,
        ICollection<string> errors,
        ISet<string> activeReferences,
        bool exactlyOne)
    {
        var keyword = exactlyOne ? "oneOf" : "anyOf";
        if (!schema.TryGetProperty(keyword, out var alternatives))
            return;

        var matched = 0;
        foreach (var alternative in alternatives.EnumerateArray())
        {
            var alternativeErrors = new List<string>();
            Validate(alternative, instance, path, rootSchema, alternativeErrors, new HashSet<string>(activeReferences, StringComparer.Ordinal));
            if (alternativeErrors.Count == 0)
                matched++;
        }

        if ((exactlyOne && matched != 1) || (!exactlyOne && matched == 0))
            errors.Add($"{path} matches {matched} {keyword} alternatives; expected {(exactlyOne ? "exactly one" : "at least one")}.");
    }

    private static void ValidateScalarConstraints(JsonElement schema, JsonElement instance, string path, ICollection<string> errors)
    {
        if (instance.ValueKind == JsonValueKind.String)
        {
            var value = instance.GetString() ?? string.Empty;
            var length = value.EnumerateRunes().Count();
            ValidateIntegerConstraint(schema, "minLength", length, path, errors);
            ValidateIntegerConstraint(schema, "maxLength", length, path, errors);

            if (schema.TryGetProperty("pattern", out var pattern) && !Regex.IsMatch(value, pattern.GetString() ?? string.Empty))
                errors.Add($"{path} does not match pattern '{pattern.GetString()}'.");

            if (schema.TryGetProperty("format", out var format) && !MatchesFormat(value, format.GetString()))
                errors.Add($"{path} does not match format '{format.GetString()}'.");
        }

        if (instance.ValueKind == JsonValueKind.Number && instance.TryGetDecimal(out var number))
        {
            ValidateNumberConstraint(schema, "minimum", number, path, errors, inclusive: true, lowerBound: true);
            ValidateNumberConstraint(schema, "maximum", number, path, errors, inclusive: true, lowerBound: false);
            ValidateNumberConstraint(schema, "exclusiveMinimum", number, path, errors, inclusive: false, lowerBound: true);
            ValidateNumberConstraint(schema, "exclusiveMaximum", number, path, errors, inclusive: false, lowerBound: false);

            if (schema.TryGetProperty("multipleOf", out var multipleOf) && multipleOf.TryGetDecimal(out var divisor) && divisor != 0 && number % divisor != 0)
                errors.Add($"{path} is not a multiple of {divisor}.");
        }

        if (instance.ValueKind == JsonValueKind.Array)
        {
            ValidateIntegerConstraint(schema, "minItems", instance.GetArrayLength(), path, errors);
            ValidateIntegerConstraint(schema, "maxItems", instance.GetArrayLength(), path, errors);

            if (schema.TryGetProperty("uniqueItems", out var uniqueItems) && uniqueItems.ValueKind == JsonValueKind.True)
            {
                var items = instance.EnumerateArray().ToArray();
                if (items.Select(item => item.GetRawText()).Distinct(StringComparer.Ordinal).Count() != items.Length)
                    errors.Add($"{path} contains duplicate items.");
            }
        }
    }

    private static void ValidateIntegerConstraint(JsonElement schema, string keyword, int value, string path, ICollection<string> errors)
    {
        if (schema.TryGetProperty(keyword, out var constraint) && constraint.TryGetInt32(out var expected))
        {
            var failed = keyword.StartsWith("min", StringComparison.Ordinal) ? value < expected : value > expected;
            if (failed)
                errors.Add($"{path} violates {keyword} {expected}.");
        }
    }

    private static void ValidateNumberConstraint(JsonElement schema, string keyword, decimal value, string path, ICollection<string> errors, bool inclusive, bool lowerBound)
    {
        if (!schema.TryGetProperty(keyword, out var constraint) || !constraint.TryGetDecimal(out var expected))
            return;

        var failed = lowerBound
            ? (inclusive ? value < expected : value <= expected)
            : (inclusive ? value > expected : value >= expected);
        if (failed)
            errors.Add($"{path} violates {keyword} {expected.ToString(CultureInfo.InvariantCulture)}.");
    }

    private static bool MatchesFormat(string value, string? format) => format switch
    {
        "date-time" => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _),
        "date" => DateOnly.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out _),
        "time" => TimeOnly.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out _),
        "uri" or "uri-reference" => Uri.TryCreate(value, UriKind.RelativeOrAbsolute, out _),
        "email" => MailAddress.TryCreate(value, out _),
        _ => true
    };

    private static bool TryResolveJsonPointer(JsonElement rootSchema, string pointer, out JsonElement resolved)
    {
        resolved = rootSchema;
        if (pointer.Length == 0)
            return true;

        if (!pointer.StartsWith("/", StringComparison.Ordinal))
        {
            resolved = default;
            return false;
        }

        foreach (var segment in pointer[1..].Split('/'))
        {
            var propertyName = segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
            if (resolved.ValueKind != JsonValueKind.Object || !resolved.TryGetProperty(propertyName, out resolved))
            {
                resolved = default;
                return false;
            }
        }

        return true;
    }

    private static void AssertSupportedSchemaKeywords(JsonElement schema, string schemaFile)
    {
        var supported = new HashSet<string>(StringComparer.Ordinal)
        {
            "$schema", "$id", "$ref", "$defs", "definitions", "title", "description", "$comment",
            "type", "enum", "const", "required", "properties", "additionalProperties", "items", "prefixItems",
            "allOf", "anyOf", "oneOf", "not", "pattern", "format", "minLength", "maxLength", "minimum",
            "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minItems", "maxItems", "uniqueItems"
        };

        var pending = new Queue<JsonElement>();
        pending.Enqueue(schema);
        while (pending.Count > 0)
        {
            var current = pending.Dequeue();
            foreach (var property in current.EnumerateObject())
            {
                Assert.True(supported.Contains(property.Name), $"{schemaFile} uses unsupported schema keyword '{property.Name}'.");
                EnqueueSubschemas(property, pending);
            }
        }
    }

    private static void EnqueueSubschemas(JsonProperty property, Queue<JsonElement> pending)
    {
        switch (property.Name)
        {
            case "properties":
            case "$defs":
            case "definitions":
                if (property.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var child in property.Value.EnumerateObject().Select(child => child.Value))
                        if (child.ValueKind == JsonValueKind.Object)
                            pending.Enqueue(child);
                }
                break;
            case "items":
            case "additionalProperties":
            case "not":
                if (property.Value.ValueKind == JsonValueKind.Object)
                    pending.Enqueue(property.Value);
                break;
            case "prefixItems":
            case "allOf":
            case "anyOf":
            case "oneOf":
                if (property.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var child in property.Value.EnumerateArray())
                        if (child.ValueKind == JsonValueKind.Object)
                            pending.Enqueue(child);
                }
                break;
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

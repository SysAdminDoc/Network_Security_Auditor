using System.Globalization;
using System.IO;
using System.Text.Json;
using Microsoft.VisualBasic.FileIO;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Services;

public static class IntuneStigAuditImporter
{
    internal const long MaxImportBytes = 50 * 1_024 * 1_024;

    public static async Task<IntuneStigAuditImport> LoadAsync(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new IntuneStigAuditImport { ImportStatus = "NotConfigured" };

        if (!File.Exists(path))
            throw new FileNotFoundException("Intune STIG audit import file was not found.", path);

        ImportFileGuard.EnsureWithinSizeLimit(path, MaxImportBytes, "Intune STIG audit import");
        var extension = Path.GetExtension(path);
        return extension.Equals(".csv", StringComparison.OrdinalIgnoreCase)
            ? LoadCsv(path)
            : await LoadJsonAsync(path);
    }

    private static async Task<IntuneStigAuditImport> LoadJsonAsync(string path)
    {
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = doc.RootElement;
        var import = new IntuneStigAuditImport
        {
            Source = GetString(root, "source", "Source", "reportName") ?? "Intune STIG audit baseline",
            SourceUrl = GetString(root, "source_url", "sourceUrl") ?? "https://learn.microsoft.com/en-us/intune/device-security/security-baselines/stig-audit-baseline",
            BaselineName = GetString(root, "baseline_name", "baselineName", "displayName") ?? "",
            BaselineVersion = GetString(root, "baseline_version", "baselineVersion", "displayVersion") ?? "",
            TenantId = GetString(root, "tenant_id", "tenantId") ?? "",
            PolicyId = GetString(root, "policy_id", "policyId") ?? "",
            ExportedAtUtc = NormalizeTimestamp(GetString(root, "exported_at_utc", "exportedAtUtc", "exportedAt", "createdDateTime")),
            ImportStatus = NormalizeImportStatus(GetString(root, "import_status", "importStatus", "status") ?? "Imported")
        };

        var rows = EnumerateRows(root).ToArray();
        foreach (var row in rows)
        {
            var finding = FromJsonRow(row, import);
            if (!string.IsNullOrWhiteSpace(finding.SettingId) || !string.IsNullOrWhiteSpace(finding.ReferenceId))
                import.Findings.Add(finding);
        }

        if (rows.Length == 0 && import.ImportStatus == "Imported")
            import.ImportStatus = "NoData";

        return import;
    }

    private static IntuneStigAuditImport LoadCsv(string path)
    {
        using var parser = new TextFieldParser(path);
        parser.SetDelimiters(",");
        parser.HasFieldsEnclosedInQuotes = true;
        var headers = parser.ReadFields() ?? [];
        var import = new IntuneStigAuditImport
        {
            Source = "Intune STIG audit baseline CSV",
            SourceUrl = "https://learn.microsoft.com/en-us/intune/device-security/security-baselines/stig-audit-baseline",
            ExportedAtUtc = File.GetLastWriteTimeUtc(path).ToString("o", CultureInfo.InvariantCulture)
        };

        while (!parser.EndOfData)
        {
            var fields = parser.ReadFields() ?? [];
            var row = headers
                .Select((header, index) => new { header, value = index < fields.Length ? fields[index] : "" })
                .ToDictionary(item => item.header, item => item.value, StringComparer.OrdinalIgnoreCase);

            var finding = FromDictionaryRow(row, import);
            if (!string.IsNullOrWhiteSpace(finding.SettingId) || !string.IsNullOrWhiteSpace(finding.ReferenceId))
                import.Findings.Add(finding);
        }

        if (import.Findings.Count == 0)
            import.ImportStatus = "NoData";

        return import;
    }

    private static IEnumerable<JsonElement> EnumerateRows(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
            return root.EnumerateArray();

        foreach (var name in new[] { "findings", "results", "rows", "values", "data" })
        {
            if (root.TryGetProperty(name, out var rows) && rows.ValueKind == JsonValueKind.Array)
                return rows.EnumerateArray();
        }

        return [];
    }

    private static IntuneStigAuditFinding FromJsonRow(JsonElement row, IntuneStigAuditImport import)
    {
        var status = NormalizeStatus(GetString(row, "status", "MaxSettingStatus", "max_setting_status", "DeviceStatus", "Result") ?? "Unknown");
        return new IntuneStigAuditFinding
        {
            DeviceName = GetString(row, "device_name", "DeviceName", "deviceName") ?? "",
            DeviceId = GetString(row, "device_id", "DeviceId", "deviceId") ?? "",
            SettingId = GetString(row, "setting_id", "SettingId", "settingId") ?? "",
            SettingName = GetString(row, "setting_name", "SettingName", "settingName", "Settings name") ?? "",
            ReferenceId = GetString(row, "reference_id", "ReferenceId", "referenceId", "StigRuleId", "stig_rule_id") ?? "",
            Severity = NormalizeSeverity(GetString(row, "severity", "Severity", "StigSeverity", "stig_severity")),
            Status = status,
            XccdfResult = ToXccdfResult(status),
            LastCheckInUtc = NormalizeTimestamp(GetString(row, "last_check_in_utc", "LastCheckInUtc", "PspdpuLastModifiedTimeUtc", "pspdpu_last_modified_time_utc")),
            SourcePolicyId = GetString(row, "policy_id", "PolicyId", "policyId") ?? import.PolicyId,
            SourceTenantId = GetString(row, "tenant_id", "TenantId", "tenantId") ?? import.TenantId
        };
    }

    private static IntuneStigAuditFinding FromDictionaryRow(IReadOnlyDictionary<string, string> row, IntuneStigAuditImport import)
    {
        var status = NormalizeStatus(GetValue(row, "Status", "MaxSettingStatus", "DeviceStatus", "Result"));
        return new IntuneStigAuditFinding
        {
            DeviceName = GetValue(row, "Device name", "DeviceName", "deviceName"),
            DeviceId = GetValue(row, "Intune Device ID", "DeviceId", "deviceId"),
            SettingId = GetValue(row, "SettingId", "Setting ID", "settingId"),
            SettingName = GetValue(row, "Settings name", "SettingName", "settingName"),
            ReferenceId = GetValue(row, "Reference ID", "ReferenceId", "StigRuleId"),
            Severity = NormalizeSeverity(GetValue(row, "Severity", "StigSeverity")),
            Status = status,
            XccdfResult = ToXccdfResult(status),
            LastCheckInUtc = NormalizeTimestamp(GetValue(row, "Last check-in time", "PspdpuLastModifiedTimeUtc")),
            SourcePolicyId = GetValue(row, "PolicyId", "Policy ID", "policyId") is { Length: > 0 } policyId ? policyId : import.PolicyId,
            SourceTenantId = GetValue(row, "TenantId", "Tenant ID", "tenantId") is { Length: > 0 } tenantId ? tenantId : import.TenantId
        };
    }

    private static string? GetString(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (!element.TryGetProperty(name, out var value))
                continue;

            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number => value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            };
        }

        return null;
    }

    private static string GetValue(IReadOnlyDictionary<string, string> row, params string[] names)
    {
        foreach (var name in names)
        {
            if (row.TryGetValue(name, out var value))
                return value.Trim();
        }

        return "";
    }

    private static string NormalizeImportStatus(string value) => value.Trim().ToLowerInvariant() switch
    {
        "notlicensed" or "not_licensed" or "not licensed" => "NotLicensed",
        "notpermitted" or "not_permitted" or "not permitted" or "forbidden" => "NotPermitted",
        "notconfigured" or "not_configured" or "not configured" => "NotConfigured",
        "nodata" or "no_data" or "no data" => "NoData",
        _ => "Imported"
    };

    private static string NormalizeStatus(string value) => value.Trim().ToLowerInvariant() switch
    {
        "success" or "succeeded" or "passed" or "pass" => "Pass",
        "failed" or "fail" => "Fail",
        "not applicable" or "notapplicable" or "not_applicable" or "n/a" => "NotApplicable",
        "error" => "Error",
        "conflict" => "Conflict",
        "notlicensed" or "not_licensed" or "not licensed" => "NotLicensed",
        "notpermitted" or "not_permitted" or "not permitted" or "forbidden" => "NotPermitted",
        _ => "Unknown"
    };

    private static string NormalizeSeverity(string? value) => (value ?? "").Trim().ToLowerInvariant() switch
    {
        "cat i" or "cati" or "high" => "high",
        "cat ii" or "catii" or "medium" => "medium",
        "cat iii" or "catiii" or "low" => "low",
        _ => value?.Trim() ?? ""
    };

    private static string NormalizeTimestamp(string? value)
    {
        if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            return parsed.ToString("o", CultureInfo.InvariantCulture);
        return value ?? "";
    }

    private static string ToXccdfResult(string status) => status switch
    {
        "Pass" => "pass",
        "Fail" => "fail",
        "NotApplicable" => "notapplicable",
        "Error" => "error",
        "Conflict" => "error",
        _ => "unknown"
    };
}

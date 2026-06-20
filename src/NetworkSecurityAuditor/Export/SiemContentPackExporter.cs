using System.IO;
using System.Text;
using System.Text.Json;

namespace NetworkSecurityAuditor.Export;

public static class SiemContentPackExporter
{
    public static string ExportAll(string outputDir)
    {
        Directory.CreateDirectory(outputDir);
        var files = new List<string>();

        var splunk = ExportSplunk();
        var splunkPath = Path.Combine(outputDir, "splunk_props.conf");
        File.WriteAllText(splunkPath, splunk);
        files.Add(splunkPath);

        var elastic = ExportElastic();
        var elasticPath = Path.Combine(outputDir, "elastic_index_template.json");
        File.WriteAllText(elasticPath, elastic);
        files.Add(elasticPath);

        var sentinel = ExportSentinel();
        var sentinelPath = Path.Combine(outputDir, "sentinel_table.json");
        File.WriteAllText(sentinelPath, sentinel);
        files.Add(sentinelPath);

        var wazuh = ExportWazuh();
        var wazuhPath = Path.Combine(outputDir, "wazuh_decoder_rules.xml");
        File.WriteAllText(wazuhPath, wazuh);
        files.Add(wazuhPath);

        var mapping = ExportFieldMapping();
        var mappingPath = Path.Combine(outputDir, "field_mapping.json");
        File.WriteAllText(mappingPath, mapping);
        files.Add(mappingPath);

        return string.Join("\n", files);
    }

    private static string ExportSplunk() => """
        [network_security_auditor]
        SHOULD_LINEMERGE = false
        LINE_BREAKER = ([\r\n]+)
        NO_BINARY_CHECK = true
        TIME_FORMAT = %Y-%m-%dT%H:%M:%S
        TIME_PREFIX = "timestamp":"
        TRUNCATE = 50000

        [network_security_auditor_transforms]
        REGEX = ^(.*)$
        FORMAT = $1
        WRITE_META = true

        # Field extractions from JSONL events
        # Import the *_siem.jsonl file as sourcetype=network_security_auditor
        # Fields: check_id, category, severity, status, findings, evidence,
        #         cis, nist, cmmc, hipaa, pci, soc2, iso27001, stig, fedramp,
        #         mitre_tactics, mitre_techniques, d3fend_stages, d3fend_techniques,
        #         overall_score, overall_grade, host, domain, scan_profile
        """;

    private static string ExportElastic()
    {
        var template = new
        {
            index_patterns = new[] { "network-security-auditor-*" },
            template = new
            {
                settings = new { number_of_shards = 1, number_of_replicas = 0 },
                mappings = new
                {
                    properties = new Dictionary<string, object>
                    {
                        ["timestamp"] = new { type = "date" },
                        ["check_id"] = new { type = "keyword" },
                        ["category"] = new { type = "keyword" },
                        ["severity"] = new { type = "keyword" },
                        ["status"] = new { type = "keyword" },
                        ["findings"] = new { type = "text" },
                        ["evidence"] = new { type = "text" },
                        ["host"] = new { type = "keyword" },
                        ["domain"] = new { type = "keyword" },
                        ["scan_profile"] = new { type = "keyword" },
                        ["overall_score"] = new { type = "integer" },
                        ["overall_grade"] = new { type = "keyword" },
                        ["cis"] = new { type = "keyword" },
                        ["nist"] = new { type = "keyword" },
                        ["cmmc"] = new { type = "keyword" },
                        ["stig"] = new { type = "keyword" },
                        ["mitre_tactics"] = new { type = "keyword" },
                        ["mitre_techniques"] = new { type = "keyword" },
                        ["d3fend_stages"] = new { type = "keyword" },
                        ["d3fend_techniques"] = new { type = "keyword" }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(template, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
    }

    private static string ExportSentinel()
    {
        var table = new
        {
            name = "NetworkSecurityAuditor_CL",
            description = "Network Security Auditor findings from JSONL export",
            columns = new[]
            {
                new { name = "TimeGenerated", type = "datetime" },
                new { name = "CheckId_s", type = "string" },
                new { name = "Category_s", type = "string" },
                new { name = "Severity_s", type = "string" },
                new { name = "Status_s", type = "string" },
                new { name = "Findings_s", type = "string" },
                new { name = "Evidence_s", type = "string" },
                new { name = "Host_s", type = "string" },
                new { name = "Domain_s", type = "string" },
                new { name = "OverallScore_d", type = "int" },
                new { name = "OverallGrade_s", type = "string" },
                new { name = "MitreTactics_s", type = "string" },
                new { name = "MitreTechniques_s", type = "string" }
            }
        };

        return JsonSerializer.Serialize(table, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string ExportWazuh() => """
        <!-- Network Security Auditor decoder -->
        <decoder name="network-security-auditor">
          <prematch>\"event_type\":\"security_finding\"</prematch>
          <regex type="pcre2">\"check_id\":\"(\w+)\".*\"severity\":\"(\w+)\".*\"status\":\"(\w+)\"</regex>
          <order>check_id,severity,status</order>
        </decoder>

        <!-- Network Security Auditor rules -->
        <group name="network-security-auditor,">
          <rule id="100800" level="3">
            <decoded_as>network-security-auditor</decoded_as>
            <description>Network Security Auditor finding</description>
          </rule>

          <rule id="100801" level="10">
            <if_sid>100800</if_sid>
            <field name="severity">Critical</field>
            <field name="status">Fail</field>
            <description>Critical security check failed: $(check_id)</description>
          </rule>

          <rule id="100802" level="7">
            <if_sid>100800</if_sid>
            <field name="severity">High</field>
            <field name="status">Fail</field>
            <description>High severity security check failed: $(check_id)</description>
          </rule>

          <rule id="100803" level="5">
            <if_sid>100800</if_sid>
            <field name="status">Partial</field>
            <description>Security check partially passed: $(check_id)</description>
          </rule>
        </group>
        """;

    private static string ExportFieldMapping()
    {
        var mapping = new
        {
            tool = "NetworkSecurityAuditor",
            version = VersionInfo.Version,
            source_format = "JSONL (one event per finding)",
            source_file_pattern = "*_siem.jsonl",
            fields = new[]
            {
                new { field = "event_type", type = "string", description = "Always 'security_finding'" },
                new { field = "tool", type = "string", description = "Tool name" },
                new { field = "tool_version", type = "string", description = "Tool version" },
                new { field = "timestamp", type = "datetime", description = "ISO 8601 scan timestamp" },
                new { field = "host", type = "string", description = "Scanned hostname" },
                new { field = "os", type = "string", description = "OS caption" },
                new { field = "domain", type = "string", description = "Domain name" },
                new { field = "scan_profile", type = "string", description = "Scan profile used" },
                new { field = "overall_score", type = "integer", description = "Overall security score 0-100" },
                new { field = "overall_grade", type = "string", description = "Letter grade A-F" },
                new { field = "check_id", type = "string", description = "Check identifier (e.g. EP01, IA03)" },
                new { field = "category", type = "string", description = "Security domain category" },
                new { field = "severity", type = "string", description = "Critical/High/Medium/Low" },
                new { field = "status", type = "string", description = "Pass/Fail/Partial/NA" },
                new { field = "findings", type = "string", description = "Finding text (max 4000 chars)" },
                new { field = "evidence", type = "string", description = "Evidence text (max 2000 chars)" },
                new { field = "cis", type = "string", description = "CIS Controls mapping" },
                new { field = "nist", type = "string", description = "NIST 800-171 control mapping" },
                new { field = "mitre_tactics", type = "array", description = "MITRE ATT&CK tactic IDs" },
                new { field = "mitre_techniques", type = "array", description = "MITRE ATT&CK technique IDs" },
                new { field = "d3fend_stages", type = "array", description = "MITRE D3FEND stage names" },
                new { field = "d3fend_techniques", type = "array", description = "MITRE D3FEND technique IDs" }
            }
        };

        return JsonSerializer.Serialize(mapping, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
    }
}

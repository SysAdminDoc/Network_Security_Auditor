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
                        ["event_type"] = new { type = "keyword" },
                        ["tool"] = new { type = "keyword" },
                        ["tool_version"] = new { type = "keyword" },
                        ["check_id"] = new { type = "keyword" },
                        ["label"] = new { type = "text" },
                        ["category"] = new { type = "keyword" },
                        ["severity"] = new { type = "keyword" },
                        ["status"] = new { type = "keyword" },
                        ["findings"] = new { type = "text" },
                        ["findings_truncated"] = new { type = "boolean" },
                        ["evidence"] = new { type = "text" },
                        ["evidence_truncated"] = new { type = "boolean" },
                        ["host"] = new { type = "keyword" },
                        ["os"] = new { type = "keyword" },
                        ["domain"] = new { type = "keyword" },
                        ["scan_profile"] = new { type = "keyword" },
                        ["overall_score"] = new { type = "integer" },
                        ["overall_grade"] = new { type = "keyword" },
                        ["cis"] = new { type = "keyword" },
                        ["nist"] = new { type = "keyword" },
                        ["cmmc"] = new { type = "keyword" },
                        ["hipaa"] = new { type = "keyword" },
                        ["pci"] = new { type = "keyword" },
                        ["soc2"] = new { type = "keyword" },
                        ["iso27001"] = new { type = "keyword" },
                        ["stig"] = new { type = "keyword" },
                        ["fedramp"] = new { type = "keyword" },
                        ["e8"] = new { type = "keyword" },
                        ["cyber_essentials"] = new { type = "keyword" },
                        ["mitre_tactics"] = new { type = "keyword" },
                        ["mitre_techniques"] = new { type = "keyword" },
                        ["d3fend_stages"] = new { type = "keyword" },
                        ["d3fend_techniques"] = new { type = "keyword" },
                        ["duration_ms"] = new { type = "double" }
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
                new { name = "EventType_s", type = "string" },
                new { name = "Tool_s", type = "string" },
                new { name = "ToolVersion_s", type = "string" },
                new { name = "CheckId_s", type = "string" },
                new { name = "Label_s", type = "string" },
                new { name = "Category_s", type = "string" },
                new { name = "Severity_s", type = "string" },
                new { name = "Status_s", type = "string" },
                new { name = "Findings_s", type = "string" },
                new { name = "FindingsTruncated_b", type = "boolean" },
                new { name = "Evidence_s", type = "string" },
                new { name = "EvidenceTruncated_b", type = "boolean" },
                new { name = "Host_s", type = "string" },
                new { name = "OS_s", type = "string" },
                new { name = "Domain_s", type = "string" },
                new { name = "ScanProfile_s", type = "string" },
                new { name = "OverallScore_d", type = "double" },
                new { name = "OverallGrade_s", type = "string" },
                new { name = "CIS_s", type = "string" },
                new { name = "NIST_s", type = "string" },
                new { name = "CMMC_s", type = "string" },
                new { name = "HIPAA_s", type = "string" },
                new { name = "PCI_s", type = "string" },
                new { name = "SOC2_s", type = "string" },
                new { name = "ISO27001_s", type = "string" },
                new { name = "STIG_s", type = "string" },
                new { name = "FedRAMP_s", type = "string" },
                new { name = "E8_s", type = "string" },
                new { name = "CyberEssentials_s", type = "string" },
                new { name = "MitreTactics_s", type = "string" },
                new { name = "MitreTechniques_s", type = "string" },
                new { name = "D3FendStages_s", type = "string" },
                new { name = "D3FendTechniques_s", type = "string" },
                new { name = "DurationMs_d", type = "double" }
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
                new { field = "label", type = "string", description = "Check display name" },
                new { field = "findings_truncated", type = "boolean", description = "True if findings were truncated at 4000 chars" },
                new { field = "evidence_truncated", type = "boolean", description = "True if evidence was truncated at 2000 chars" },
                new { field = "cis", type = "string", description = "CIS Controls mapping" },
                new { field = "nist", type = "string", description = "NIST 800-171 control mapping" },
                new { field = "cmmc", type = "string", description = "CMMC Level 2 control mapping" },
                new { field = "hipaa", type = "string", description = "HIPAA Security Rule mapping" },
                new { field = "pci", type = "string", description = "PCI-DSS 4.0.1 mapping" },
                new { field = "soc2", type = "string", description = "SOC 2 Type II mapping" },
                new { field = "iso27001", type = "string", description = "ISO 27001:2022 mapping" },
                new { field = "stig", type = "string", description = "DISA STIG mapping" },
                new { field = "fedramp", type = "string", description = "FedRAMP Moderate mapping" },
                new { field = "e8", type = "string", description = "ACSC Essential Eight mapping" },
                new { field = "cyber_essentials", type = "string", description = "Cyber Essentials mapping" },
                new { field = "mitre_tactics", type = "array", description = "MITRE ATT&CK tactic IDs" },
                new { field = "mitre_techniques", type = "array", description = "MITRE ATT&CK technique IDs" },
                new { field = "d3fend_stages", type = "array", description = "MITRE D3FEND stage names" },
                new { field = "d3fend_techniques", type = "array", description = "MITRE D3FEND technique IDs" },
                new { field = "duration_ms", type = "number", description = "Check execution time in milliseconds" }
            }
        };

        return JsonSerializer.Serialize(mapping, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
    }
}

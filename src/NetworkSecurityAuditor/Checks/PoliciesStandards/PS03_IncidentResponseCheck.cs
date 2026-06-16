namespace NetworkSecurityAuditor.Checks.PoliciesStandards;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// PS03 - Incident Response: Check for IR plan indicators. Check backup/DR services.
/// </summary>
public sealed class PS03_IncidentResponseCheck : ISecurityCheck
{
    public string Id => "PS03";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int indicators = 0;

            evidence.AppendLine("[Incident Response Readiness Indicators]");
            evidence.AppendLine($"  Assessed: {DateTime.Now:yyyy-MM-dd HH:mm}");

            // 1. Check for SIEM/log collection agents
            ct.ThrowIfCancellationRequested();
            CheckSiemAgents(sb, evidence, ref indicators, ct);

            // 2. Check for EDR (incident investigation capability)
            ct.ThrowIfCancellationRequested();
            CheckEdrCapability(sb, evidence, ref indicators);

            // 3. Check Windows Event Forwarding
            ct.ThrowIfCancellationRequested();
            CheckWef(sb, evidence, ref indicators, ct);

            // 4. Check audit logging
            if (env.HasDefender)
            {
                indicators++;
                evidence.AppendLine("\n  Defender for Endpoint: Available (incident response capability)");
            }

            sb.AppendLine($"\nIncident response readiness indicators found: {indicators}");
            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Incident Response Plan:");
            sb.AppendLine("  [ ] Written Incident Response (IR) plan exists");
            sb.AppendLine("  [ ] IR plan defines roles and responsibilities");
            sb.AppendLine("  [ ] IR plan covers: identification, containment, eradication, recovery");
            sb.AppendLine("  [ ] Contact lists (internal, legal, law enforcement, cyber insurance) are current");
            sb.AppendLine("  [ ] IR plan includes ransomware-specific procedures");
            sb.AppendLine("  [ ] IR plan is tested via tabletop exercises (at least annually)");
            sb.AppendLine("  [ ] Incident classification and severity levels are defined");
            sb.AppendLine("  [ ] Evidence preservation procedures are documented");
            sb.AppendLine("  [ ] Communication plan (customers, regulators, media) exists");
            sb.AppendLine("  [ ] Retainer with external IR firm is in place");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Interview IT/security team for IR plan " +
                "documentation, test results, and contact list currency.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void CheckSiemAgents(StringBuilder sb, StringBuilder evidence,
        ref int indicators, CancellationToken ct)
    {
        evidence.AppendLine("\n[SIEM/Log Collection Agents]");

        var siemKeys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Splunk", "Splunk Universal Forwarder" },
            { @"HKLM\SOFTWARE\LogRhythm", "LogRhythm" },
            { @"HKLM\SOFTWARE\Rapid7\InsightAgent", "Rapid7 InsightAgent" },
            { @"HKLM\SOFTWARE\Elastic\Agent", "Elastic Agent" },
            { @"HKLM\SOFTWARE\Wazuh", "Wazuh Agent" },
            { @"HKLM\SOFTWARE\OSSEC", "OSSEC" },
            { @"HKLM\SOFTWARE\Microsoft\Microsoft Monitoring Agent", "Microsoft Monitoring Agent" },
            { @"HKLM\SOFTWARE\Microsoft\Azure Monitor", "Azure Monitor Agent" },
        };

        foreach (var (path, label) in siemKeys)
        {
            if (RegistryHelper.KeyExists(path))
            {
                indicators++;
                evidence.AppendLine($"  FOUND: {label}");
                sb.AppendLine($"SIEM/log collection agent detected: {label}");
            }
        }
    }

    private static void CheckEdrCapability(StringBuilder sb, StringBuilder evidence, ref int indicators)
    {
        evidence.AppendLine("\n[EDR/Investigation Capability]");

        var edrKeys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection", "Defender for Endpoint" },
            { @"HKLM\SOFTWARE\CrowdStrike", "CrowdStrike Falcon" },
            { @"HKLM\SOFTWARE\SentinelOne", "SentinelOne" },
            { @"HKLM\SOFTWARE\Carbon Black", "Carbon Black" },
        };

        foreach (var (path, label) in edrKeys)
        {
            if (RegistryHelper.KeyExists(path))
            {
                indicators++;
                evidence.AppendLine($"  FOUND: {label}");
                sb.AppendLine($"EDR with IR capability detected: {label}");
            }
        }
    }

    private static void CheckWef(StringBuilder sb, StringBuilder evidence,
        ref int indicators, CancellationToken ct)
    {
        evidence.AppendLine("\n[Windows Event Forwarding]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State FROM Win32_Service WHERE Name = 'WecSvc'");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string state = obj["State"]?.ToString() ?? "Unknown";
                evidence.AppendLine($"  WEC Service: {state}");

                if (state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    indicators++;
                    sb.AppendLine("Windows Event Collector service is running (centralized log collection).");
                }
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }
}

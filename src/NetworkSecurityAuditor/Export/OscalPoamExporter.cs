using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

/// <summary>
/// NIST OSCAL Plan of Action and Milestones exporter.
/// Produces risk and remediation-task records linked to OSCAL assessment finding UUIDs.
/// </summary>
public static class OscalPoamExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(
        IEnumerable<CheckItemViewModel> checks,
        EnvironmentInfo env,
        IReadOnlyDictionary<string, RiskWaiver>? activeWaivers = null)
    {
        var timestamp = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        var toolPartyUuid = OscalIds.Party("tool", "Network Security Auditor");
        var parties = new List<object>
        {
            new { uuid = toolPartyUuid, type = "tool", name = $"Network Security Auditor v{VersionInfo.Version}" }
        };
        var partyUuids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string AddPersonParty(string role, string name)
        {
            var key = $"{role}\u001f{name}";
            if (partyUuids.TryGetValue(key, out var existing))
                return existing;

            var uuid = OscalIds.Party(role, name);
            partyUuids[key] = uuid;
            parties.Add(new { uuid, type = "person", name });
            return uuid;
        }

        var risks = new List<object>();
        var poamItems = new List<object>();

        foreach (var check in checks.Where(check => ShouldInclude(check, activeWaivers)))
        {
            RiskWaiver? waiver = null;
            activeWaivers?.TryGetValue(check.Id, out waiver);
            var acceptedRisk = waiver is not null || HasAcceptedRiskNote(check);
            var findingUuid = OscalIds.Finding(env, check);
            var riskUuid = OscalIds.Risk(env, check);
            var itemUuid = OscalIds.PoamItem(env, check);
            var statusValue = StatusValue(check.Status);

            var riskProps = new List<object>
            {
                Prop("check-id", check.Id),
                Prop("finding-uuid", findingUuid),
                Prop("finding-status", statusValue),
                Prop("severity", SeverityValue(check.Severity)),
                Prop("evidence-mode", check.EvidenceMode.ToString()),
                Prop("waiver-status", acceptedRisk ? "active" : "none")
            };
            AddWaiverProps(riskProps, waiver);

            risks.Add(new
            {
                uuid = riskUuid,
                title = $"[{check.Id}] {check.Label}",
                description = NonEmpty(check.Findings, $"Security finding for {check.Id}."),
                statement = $"{check.Id} is {statusValue} on {env.ComputerName}.",
                status = acceptedRisk ? "accepted" : "open",
                props = riskProps,
                characterizations = new[]
                {
                    new
                    {
                        origin = new
                        {
                            actors = new[] { new { type = "tool", actorUuid = toolPartyUuid } }
                        },
                        facets = new[]
                        {
                            new { name = "severity", value = SeverityValue(check.Severity) },
                            new { name = "status", value = statusValue }
                        }
                    }
                }
            });

            var itemProps = new List<object>
            {
                Prop("check-id", check.Id),
                Prop("finding-uuid", findingUuid),
                Prop("risk-uuid", riskUuid),
                Prop("waiver-status", acceptedRisk ? "active" : "none")
            };
            AddWaiverProps(itemProps, waiver);

            string[]? responsiblePartyUuids = null;
            if (!string.IsNullOrWhiteSpace(check.RemediationAssignee))
            {
                responsiblePartyUuids = [AddPersonParty("owner", check.RemediationAssignee.Trim())];
                itemProps.Add(Prop("remediation-owner", check.RemediationAssignee.Trim()));
            }

            object[]? milestones = null;
            if (check.RemediationDueDate is { } dueDate)
            {
                var dueDateText = dueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                itemProps.Add(Prop("remediation-due-date", dueDateText));
                milestones =
                [
                    new
                    {
                        uuid = OscalIds.Milestone(env, check, "remediation-due"),
                        title = "Remediation due",
                        description = $"Target remediation date for {check.Id}.",
                        dueDate = dueDateText
                    }
                ];
            }

            poamItems.Add(new
            {
                uuid = itemUuid,
                title = $"Remediate {check.Id}: {check.Label}",
                description = BuildRemediationText(check, waiver, acceptedRisk),
                props = itemProps,
                relatedRisks = new[] { new { riskUuid } },
                responsibleParties = responsiblePartyUuids is null ? null : new[]
                {
                    new { roleId = "owner", partyUuids = responsiblePartyUuids }
                },
                milestones
            });
        }

        var poam = new
        {
            planOfActionAndMilestones = new
            {
                uuid = Guid.NewGuid().ToString(),
                metadata = new
                {
                    title = $"Security POA&M - {env.ComputerName}",
                    lastModified = timestamp,
                    version = "1.0.0",
                    oscalVersion = "1.1.3",
                    roles = new[]
                    {
                        new { id = "assessor", title = "Security Assessor" },
                        new { id = "owner", title = "Remediation Owner" },
                        new { id = "approver", title = "Risk Acceptance Approver" }
                    },
                    parties
                },
                systemId = new
                {
                    identifierType = "https://sysadmindoc.github.io/network-security-auditor/system-id/computer-name",
                    id = env.ComputerName
                },
                risks,
                poamItems
            }
        };

        return JsonSerializer.Serialize(poam, Options);
    }

    private static bool ShouldInclude(CheckItemViewModel check, IReadOnlyDictionary<string, RiskWaiver>? activeWaivers)
    {
        if (check.Status is CheckStatus.Fail or CheckStatus.Partial)
            return true;

        return (activeWaivers?.ContainsKey(check.Id) ?? false) || HasAcceptedRiskNote(check);
    }

    private static void AddWaiverProps(List<object> props, RiskWaiver? waiver)
    {
        if (waiver is null)
            return;

        props.Add(Prop("waiver-justification", waiver.Justification));
        props.Add(Prop("waiver-approved-by", waiver.ApprovedBy));
        props.Add(Prop("waiver-approved-date", waiver.ApprovedDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        if (waiver.ExpirationDate is { } expiration)
            props.Add(Prop("waiver-expiration-date", expiration.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
    }

    private static string BuildRemediationText(CheckItemViewModel check, RiskWaiver? waiver, bool acceptedRisk)
    {
        if (acceptedRisk && waiver is not null)
            return $"Accepted risk: {waiver.Justification}";

        if (!string.IsNullOrWhiteSpace(check.Notes))
            return check.Notes.Trim();

        if (!string.IsNullOrWhiteSpace(check.RemediationUrl))
            return $"Review remediation guidance at {check.RemediationUrl}.";

        return $"Review and remediate {check.Label}.";
    }

    private static bool HasAcceptedRiskNote(CheckItemViewModel check)
        => check.Notes.StartsWith("[ACCEPTED RISK]", StringComparison.OrdinalIgnoreCase);

    private static string NonEmpty(string value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static string StatusValue(CheckStatus status) => status switch
    {
        CheckStatus.Fail => "fail",
        CheckStatus.Partial => "partial",
        CheckStatus.Pass => "pass",
        CheckStatus.NA => "not-applicable",
        _ => "not-assessed"
    };

    private static string SeverityValue(Severity severity) => severity switch
    {
        Severity.Critical => "critical",
        Severity.High => "high",
        Severity.Medium => "medium",
        Severity.Low => "low",
        _ => "unknown"
    };

    private static object Prop(string name, string value) => new { name, value };
}

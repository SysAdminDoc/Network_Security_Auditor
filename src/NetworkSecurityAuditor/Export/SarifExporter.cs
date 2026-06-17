using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class SarifExporter
{
    public static string Export(IEnumerable<CheckItemViewModel> checks, EnvironmentInfo env)
    {
        var checkList = checks.ToList();

        var rules = checkList.Select(c =>
        {
            var mapping = FrameworkMappings.All.GetValueOrDefault(c.Id);
            var mitre = MitreMappings.All.GetValueOrDefault(c.Id);

            return new
            {
                id = c.Id,
                name = c.Label,
                shortDescription = new { text = c.Label },
                fullDescription = new { text = CheckCatalog.All.TryGetValue(c.Id, out var meta) ? meta.Hint : c.Label },
                defaultConfiguration = new
                {
                    level = c.Severity switch
                    {
                        Severity.Critical => "error",
                        Severity.High => "error",
                        Severity.Medium => "warning",
                        _ => "note"
                    }
                },
                properties = new Dictionary<string, object?>
                {
                    ["category"] = c.Category,
                    ["severity"] = c.Severity.ToString(),
                    ["weight"] = c.Weight,
                    ["compliance"] = mapping?.FormatAll(),
                    ["mitre-attack"] = mitre is not null ? string.Join(", ", mitre.Techniques) : null
                }
            };
        }).ToArray();

        var results = checkList
            .Where(c => c.Status is CheckStatus.Fail or CheckStatus.Partial)
            .Select(c => new
            {
                ruleId = c.Id,
                level = c.Status == CheckStatus.Fail
                    ? (c.Severity >= Severity.High ? "error" : "warning")
                    : "warning",
                message = new { text = TruncateForSarif(c.Findings, 4000) },
                locations = new[]
                {
                    new
                    {
                        logicalLocations = new[]
                        {
                            new
                            {
                                fullyQualifiedName = $"network-security-audit://{c.Category}/{c.Id}",
                                kind = "securityCheck"
                            }
                        }
                    }
                },
                partialFingerprints = new Dictionary<string, string>
                {
                    ["primaryLocationLineHash"] = ComputeFingerprint($"{c.Id}:{env.ComputerName}")
                },
                properties = new Dictionary<string, object?>
                {
                    ["status"] = c.Status.ToString(),
                    ["evidence"] = TruncateForSarif(c.Evidence, 2000),
                    ["category"] = c.Category,
                    ["severity"] = c.Severity.ToString()
                }
            }).ToArray();

        var sarif = new
        {
            schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            version = "2.1.0",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "Network Security Auditor",
                            version = "5.0.0",
                            informationUri = "https://github.com/SysAdminDoc/Network_Security_Auditor",
                            rules
                        }
                    },
                    results,
                    invocations = new[]
                    {
                        new
                        {
                            executionSuccessful = true,
                            endTimeUtc = DateTime.UtcNow.ToString("o"),
                            properties = new Dictionary<string, object>
                            {
                                ["host"] = env.ComputerName,
                                ["os"] = env.OSCaption,
                                ["domain"] = env.DomainName,
                                ["isAdmin"] = env.IsAdmin
                            }
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(sarif, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    private static string TruncateForSarif(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= maxLength ? text : text[..maxLength] + "... [truncated]";
    }

    private static string ComputeFingerprint(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

public static class NavigatorExporter
{
    public static string Export(IEnumerable<CheckItemViewModel> checks)
    {
        var checkList = checks.ToList();
        var statusLookup = checkList.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);

        var techniqueScores = new Dictionary<string, (int worstScore, CheckStatus worstStatus, List<string> checkIds)>(StringComparer.OrdinalIgnoreCase);

        foreach (var (checkId, mapping) in MitreMappings.All)
        {
            if (!statusLookup.TryGetValue(checkId, out var status))
                continue;

            int score = status switch
            {
                CheckStatus.Pass => 100,
                CheckStatus.Partial => 50,
                CheckStatus.Fail => 0,
                _ => -1
            };

            foreach (var techId in mapping.Techniques)
            {
                if (techniqueScores.TryGetValue(techId, out var existing))
                {
                    if (score < existing.worstScore)
                        techniqueScores[techId] = (score, status, [..existing.checkIds, checkId]);
                    else
                        existing.checkIds.Add(checkId);
                }
                else
                {
                    techniqueScores[techId] = (score, status, [checkId]);
                }
            }
        }

        var techniques = techniqueScores.Select(kv =>
        {
            var (techId, (worstScore, worstStatus, checkIds)) = (kv.Key, kv.Value);
            string color = worstStatus switch
            {
                CheckStatus.Pass => "#a6e3a1",
                CheckStatus.Partial => "#f9e2af",
                CheckStatus.Fail => "#f38ba8",
                _ => "#585b70"
            };

            return new
            {
                techniqueID = techId,
                score = worstScore,
                color,
                comment = string.Join(", ", checkIds.Select(id => $"[{id}]")),
                enabled = true,
                showSubtechniques = true
            };
        }).Cast<object>().ToList();

        var layer = new
        {
            name = "Network Security Auditor Coverage",
            versions = new { attack = "19.0", navigator = "4.9.0", layer = "4.5" },
            domain = "enterprise-attack",
            description = $"Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC by Network Security Auditor v{VersionInfo.Version}",
            sorting = 3,
            layout = new { layout = "side", aggregateFunction = "average", showID = true, showName = true, showAggregateScores = true, countUnscored = false },
            hideDisabled = false,
            techniques,
            gradient = new
            {
                colors = new[] { "#f38ba8", "#f9e2af", "#a6e3a1" },
                minValue = 0,
                maxValue = 100
            },
            showTacticRowBackground = true,
            tacticRowBackground = "#313244",
            selectTechniquesAcrossTactics = true,
            selectSubtechniquesWithParent = false
        };

        return JsonSerializer.Serialize(layer, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }
}

using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

/// <summary>
/// SPRS (Supplier Performance Risk System) score for CMMC Level 2.
/// Methodology: start at 110, subtract weighted points per unmet NIST 800-171 control.
/// Controls are weighted 1 (low), 3 (medium), or 5 (high) based on DoD assessment guidance.
/// </summary>
public static class SprsScoreEngine
{
    private static readonly Dictionary<string, int> ControlWeights = new(StringComparer.OrdinalIgnoreCase)
    {
        // 5-point controls (critical security practices)
        ["3.1.1"] = 5, ["3.1.2"] = 5, ["3.1.5"] = 5, ["3.1.12"] = 5, ["3.1.13"] = 5, ["3.1.20"] = 5,
        ["3.5.3"] = 5, ["3.5.7"] = 5,
        ["3.13.1"] = 5, ["3.13.8"] = 5, ["3.13.11"] = 5,
        ["3.14.1"] = 5, ["3.14.2"] = 5,
        // 3-point controls (important)
        ["3.1.3"] = 3, ["3.1.6"] = 3, ["3.1.7"] = 3, ["3.1.17"] = 3,
        ["3.3.1"] = 3, ["3.3.2"] = 3, ["3.3.4"] = 3, ["3.3.5"] = 3, ["3.3.8"] = 3,
        ["3.4.1"] = 3, ["3.4.2"] = 3, ["3.4.6"] = 3, ["3.4.7"] = 3, ["3.4.8"] = 3, ["3.4.9"] = 3,
        ["3.5.1"] = 3, ["3.5.2"] = 3, ["3.5.8"] = 3, ["3.5.9"] = 3, ["3.5.10"] = 3,
        ["3.6.1"] = 3, ["3.6.2"] = 3, ["3.6.3"] = 3,
        ["3.7.5"] = 3,
        ["3.8.1"] = 3, ["3.8.6"] = 3, ["3.8.9"] = 3,
        ["3.12.1"] = 3, ["3.12.2"] = 3, ["3.12.3"] = 3, ["3.12.4"] = 3,
        ["3.13.2"] = 3, ["3.13.3"] = 3, ["3.13.5"] = 3, ["3.13.6"] = 3, ["3.13.7"] = 3, ["3.13.15"] = 3,
        ["3.14.4"] = 3, ["3.14.5"] = 3, ["3.14.6"] = 3,
    };

    public static int GetWeight(string controlId) => ControlWeights.GetValueOrDefault(controlId, 1);

    public static (int Score, string Confidence) Calculate(IEnumerable<CheckItemViewModel> checks)
    {
        var statusLookup = checks.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);
        var controlsCovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var controlsFailing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (checkId, mapping) in FrameworkMappings.All)
        {
            if (mapping.NIST is null) continue;
            if (!statusLookup.TryGetValue(checkId, out var status)) continue;
            if (status is CheckStatus.NA or CheckStatus.NotAssessed) continue;

            var controls = mapping.NIST.Split(',', StringSplitOptions.TrimEntries);
            foreach (var control in controls)
            {
                controlsCovered.Add(control);
                if (status is CheckStatus.Fail)
                    controlsFailing.Add(control);
            }
        }

        int deductions = 0;
        foreach (var control in controlsFailing)
        {
            int weight = ControlWeights.GetValueOrDefault(control, 1);
            deductions += weight;
        }

        int score = Math.Max(-203, 110 - deductions);
        string confidence = controlsCovered.Count >= 50 ? "High" : controlsCovered.Count >= 25 ? "Medium" : "Low";

        return (score, confidence);
    }
}

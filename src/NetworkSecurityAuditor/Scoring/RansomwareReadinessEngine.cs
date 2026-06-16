using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

public static class RansomwareReadinessEngine
{
    private static readonly Dictionary<string, (string[] CheckIds, double Weight)> Domains = new()
    {
        ["Prevention"] = (["EP01", "EP07", "CF02", "NP05"], 0.30),
        ["Protection"] = (["EP08", "EP05", "EP02", "CF07"], 0.25),
        ["Detection"] = (["NP07", "LM02", "LM03", "LM08"], 0.25),
        ["Recovery"] = (["BR01", "BR02", "BR03", "BR07"], 0.20)
    };

    public static (int Score, string Grade) Calculate(IEnumerable<CheckItemViewModel> checks)
    {
        var checkLookup = checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        double totalScore = 0;
        double totalWeight = 0;

        foreach (var (_, (checkIds, weight)) in Domains)
        {
            double domainEarned = 0;
            double domainPossible = 0;

            foreach (var id in checkIds)
            {
                if (!checkLookup.TryGetValue(id, out var check))
                    continue;

                if (check.Status is CheckStatus.NA or CheckStatus.NotAssessed)
                    continue;

                double statusFactor = check.Status switch
                {
                    CheckStatus.Pass => 1.0,
                    CheckStatus.Partial => 0.5,
                    CheckStatus.Fail => 0.0,
                    _ => 0.0
                };

                domainEarned += statusFactor;
                domainPossible += 1.0;
            }

            if (domainPossible > 0)
            {
                totalScore += (domainEarned / domainPossible) * weight * 100;
                totalWeight += weight;
            }
        }

        int score = totalWeight > 0 ? (int)Math.Round(totalScore / (totalWeight * 100) * 100) : 0;
        string grade = score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };

        return (score, grade);
    }
}

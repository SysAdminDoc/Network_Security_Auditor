using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

public static class RiskScoreEngine
{
    public static (int Score, string Grade) Calculate(IEnumerable<CheckItemViewModel> checks)
    {
        double earned = 0;
        double possible = 0;

        foreach (var check in checks)
        {
            if (check.Status is CheckStatus.NA or CheckStatus.NotAssessed)
                continue;

            double severityWeight = (int)check.Severity;
            double categoryWeight = CategoryWeights.GetWeight(check.Category);
            double itemPossible = severityWeight * categoryWeight * check.Weight;

            double statusFactor = check.Status switch
            {
                CheckStatus.Pass => 1.0,
                CheckStatus.Partial => 0.5,
                CheckStatus.Fail => 0.0,
                _ => 0.0
            };

            earned += itemPossible * statusFactor;
            possible += itemPossible;
        }

        int score = possible > 0 ? (int)Math.Round(earned / possible * 100) : 0;
        return (score, GradeFromScore(score));
    }

    public static string GradeFromScore(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };
}

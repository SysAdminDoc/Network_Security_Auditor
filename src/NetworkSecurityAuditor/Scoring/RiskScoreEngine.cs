using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

public static class RiskScoreEngine
{
    public static (int Score, string Grade) Calculate(IEnumerable<CheckItemViewModel> checks)
    {
        var categories = new Dictionary<string, CategoryAccumulator>(StringComparer.OrdinalIgnoreCase);

        foreach (var check in checks)
        {
            if (check.Status is CheckStatus.NA or CheckStatus.NotAssessed)
                continue;

            double itemPossible = check.Weight;

            double statusFactor = check.Status switch
            {
                CheckStatus.Pass => 1.0,
                CheckStatus.Partial => 0.5,
                CheckStatus.Fail => 0.0,
                _ => 0.0
            };

            var category = categories.GetValueOrDefault(check.Category);
            category.Earned += itemPossible * statusFactor;
            category.Possible += itemPossible;
            category.Weight = CategoryWeights.GetWeight(check.Category);
            categories[check.Category] = category;
        }

        double weightedTotal = 0;
        double assessedWeight = 0;
        foreach (var category in categories.Values)
        {
            if (category.Possible <= 0)
                continue;

            weightedTotal += (category.Earned / category.Possible * 100) * category.Weight;
            assessedWeight += category.Weight;
        }

        int score = assessedWeight > 0 ? (int)Math.Round(weightedTotal / assessedWeight) : 0;
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

    private struct CategoryAccumulator
    {
        public double Earned { get; set; }
        public double Possible { get; set; }
        public double Weight { get; set; }
    }
}

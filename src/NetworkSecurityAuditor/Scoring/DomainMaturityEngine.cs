using System.Collections.ObjectModel;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

public static class DomainMaturityEngine
{
    private static readonly (string[] checkIds, double weight)[] Domains =
    [
        (["IA01", "IA02", "IA06", "IA11", "IA12", "CF01"], 0.30),
        (["IA04", "IA05", "IA07", "IA08", "IA10", "CF04"], 0.25),
        (["EP03", "EP08", "EP04", "EP02", "EP05"], 0.25),
        (["LM02", "LM03", "LM05", "LM08"], 0.20),
    ];

    public static readonly string[] DomainNames =
    [
        "Privileged Access",
        "Identity Hygiene",
        "Infrastructure Hardening",
        "Visibility"
    ];

    public static (int score, string grade, int[] domainScores) Calculate(
        ObservableCollection<CheckItemViewModel> checks)
    {
        var lookup = checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        double totalWeighted = 0;
        double assessedWeight = 0;
        var domainScores = new int[Domains.Length];

        for (int i = 0; i < Domains.Length; i++)
        {
            var (ids, weight) = Domains[i];
            double earned = 0, possible = 0;

            foreach (var id in ids)
            {
                if (!lookup.TryGetValue(id, out var vm)) continue;
                if (vm.Status is CheckStatus.NA or CheckStatus.NotAssessed) continue;

                possible += 1.0;
                earned += vm.Status switch
                {
                    CheckStatus.Pass => 1.0,
                    CheckStatus.Partial => 0.5,
                    _ => 0.0
                };
            }

            var domainPct = possible > 0 ? earned / possible * 100 : 0;
            domainScores[i] = (int)Math.Round(domainPct);
            if (possible > 0)
            {
                totalWeighted += domainPct * weight;
                assessedWeight += weight;
            }
        }

        var score = assessedWeight > 0 ? (int)Math.Round(totalWeighted / assessedWeight) : 0;
        var grade = RiskScoreEngine.GradeFromScore(score);
        return (score, grade, domainScores);
    }
}

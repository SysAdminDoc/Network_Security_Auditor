using System.Globalization;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

public static class RansomwareReadinessEngine
{
    private const string PreventionDomain = "Prevention";
    private const string KevCheckId = "EP04";
    private const string KevExposureLabel = "Ransomware-linked KEV entries";

    private static readonly Regex KevExposurePattern = new(
        @"^\s*Ransomware-linked KEV entries: (\d+) \(overdue: (\d+)\)\s*$",
        RegexOptions.Multiline | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, (string[] CheckIds, double Weight)> Domains = new()
    {
        [PreventionDomain] = (["EP01", "EP07", "CF02", "NP05"], 0.30),
        ["Protection"] = (["EP08", "EP05", "EP02", "CF07"], 0.25),
        ["Detection"] = (["NP07", "LM02", "LM03", "LM08"], 0.25),
        ["Recovery"] = (["BR01", "BR02", "BR03", "BR07"], 0.20)
    };

    /// <summary>
    /// The line EP04 writes into its findings whenever it cross-referenced the CISA KEV feed. Scoring reads it
    /// back from the findings, so a saved or reloaded audit scores the same as the live run.
    /// </summary>
    internal static string FormatKevExposure(int ransomwareLinked, int overdue) =>
        string.Create(CultureInfo.InvariantCulture, $"{KevExposureLabel}: {ransomwareLinked} (overdue: {overdue})");

    internal static bool TryReadKevExposure(string? findings, out int ransomwareLinked, out int overdue)
    {
        ransomwareLinked = 0;
        overdue = 0;
        if (string.IsNullOrEmpty(findings))
            return false;
        var match = KevExposurePattern.Match(findings);
        return match.Success
            && int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out ransomwareLinked)
            && int.TryParse(match.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out overdue);
    }

    /// <summary>
    /// Ransomware-linked KEV exposure is one more Prevention factor, counted only when EP04 checked the feed:
    /// none scores 1, entries that aren't due yet score 0.5 and any overdue entry scores 0.
    /// </summary>
    internal static double? KevExposureFactor(CheckItemViewModel? ep04)
    {
        if (ep04 is null || !ep04.Status.IsScored() || !TryReadKevExposure(ep04.Findings, out var linked, out var overdue))
            return null;
        return overdue > 0 ? 0.0 : linked > 0 ? 0.5 : 1.0;
    }

    public static (int Score, string Grade) Calculate(IEnumerable<CheckItemViewModel> checks)
    {
        var checkLookup = checks.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        double totalScore = 0;
        double totalWeight = 0;

        foreach (var (domain, (checkIds, weight)) in Domains)
        {
            double domainEarned = 0;
            double domainPossible = 0;

            foreach (var id in checkIds)
            {
                if (!checkLookup.TryGetValue(id, out var check))
                    continue;

                if (!check.Status.IsScored())
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

            if (domain == PreventionDomain
                && KevExposureFactor(checkLookup.GetValueOrDefault(KevCheckId)) is double kevFactor)
            {
                domainEarned += kevFactor;
                domainPossible += 1.0;
            }

            if (domainPossible > 0)
            {
                totalScore += (domainEarned / domainPossible) * weight * 100;
                totalWeight += weight;
            }
        }

        int score = totalWeight > 0
            ? (int)Math.Round(totalScore / (totalWeight * 100) * 100, MidpointRounding.AwayFromZero)
            : 0;
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

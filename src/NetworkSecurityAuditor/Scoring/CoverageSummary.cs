using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Scoring;

/// <summary>
/// How much of the audit produced a scored result. Checks that don't apply (NA) are left out of the
/// denominator; unanswered questionnaire checks and checks that errored or timed out count against it.
/// </summary>
public sealed record CoverageSummary(int Total, int Scored, int NotAssessed, int Errors, int TimedOut, int NotApplicable)
{
    public int Applicable => Total - NotApplicable;

    public double Pct => Applicable > 0 ? Math.Round((double)Scored / Applicable * 100, 1) : 0.0;

    public static CoverageSummary From(IEnumerable<CheckItemViewModel> checks)
    {
        int total = 0, scored = 0, notAssessed = 0, errors = 0, timedOut = 0, notApplicable = 0;
        foreach (var check in checks)
        {
            total++;
            if (check.Status.IsScored()) scored++;
            else if (check.Status == CheckStatus.NotAssessed) notAssessed++;
            else if (check.Status == CheckStatus.NA) notApplicable++;
            else if (check.Status == CheckStatus.Error)
            {
                errors++;
                if (CheckResult.IsTimeoutEvidence(check.Evidence)) timedOut++;
            }
        }

        return new CoverageSummary(total, scored, notAssessed, errors, timedOut, notApplicable);
    }
}

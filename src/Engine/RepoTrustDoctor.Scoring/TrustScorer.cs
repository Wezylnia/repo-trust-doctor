using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Scoring;

public sealed class TrustScorer
{
    public TrustScore Score(IReadOnlyList<Finding> findings)
    {
        var categories = findings
            .GroupBy(finding => finding.Category)
            .Select(group => new CategoryScore(group.Key, ScoreCategory(group)))
            .OrderBy(score => score.Category)
            .ToArray();

        var overall = categories.Length == 0
            ? 100
            : Math.Clamp((int)Math.Round(categories.Average(category => category.Score)), 0, 100);

        var blockers = findings.Where(finding => finding.IsBlocking).ToArray();
        var critical = findings.Where(finding => finding.Severity == Severity.Critical).ToArray();
        var high = findings.Where(finding => finding.Severity == Severity.High).ToArray();

        FinalDecision decision = blockers.Length > 0 || critical.Length > 0
            ? new FinalDecision(FinalDecisionKind.AvoidAsProductionDependency, BuildReasons(blockers.Concat(critical), "Blocking or critical findings were detected."))
            : high.Length > 0 || overall < 80
                ? new FinalDecision(FinalDecisionKind.UseWithCaution, BuildReasons(high, "The scan found risks that should be reviewed before production use."))
                : new FinalDecision(FinalDecisionKind.SafeToTry, ["No high or critical findings were detected in the completed modules."]);

        return new TrustScore(overall, categories, decision);
    }

    private static int ScoreCategory(IEnumerable<Finding> findings)
    {
        var penalty = findings.Sum(finding => finding.Severity switch
        {
            Severity.Info => 0,
            Severity.Low => 5,
            Severity.Medium => 12,
            Severity.High => 25,
            Severity.Critical => 45,
            _ => 0
        });

        return Math.Clamp(100 - penalty, 0, 100);
    }

    private static IReadOnlyList<string> BuildReasons(IEnumerable<Finding> findings, string fallback)
    {
        var reasons = findings
            .Take(3)
            .Select(finding => $"{finding.RuleId}: {finding.Title}")
            .ToArray();

        return reasons.Length == 0 ? [fallback] : reasons;
    }
}

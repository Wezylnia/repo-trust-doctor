using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Policies;

namespace RepoTrustDoctor.Scoring;

public sealed class TrustScorer
{
    public TrustScore Score(IReadOnlyList<Finding> findings)
    {
        return Score(findings, TrustProfile.ProductionDependency);
    }

    public TrustScore Score(IReadOnlyList<Finding> findings, TrustProfile trustProfile)
    {
        var normalizedProfile = TrustProfileCatalog.Normalize(trustProfile);
        var policy = TrustPolicyPresets.ForProfile(normalizedProfile);
        var policyEvaluation = new TrustPolicyEvaluator().Evaluate(findings, policy);
        var categories = findings
            .GroupBy(finding => finding.Category)
            .Select(group => new CategoryScore(group.Key, ScoreCategory(group, normalizedProfile)))
            .OrderBy(score => score.Category)
            .ToArray();

        var overall = categories.Length == 0
            ? 100
            : Math.Clamp((int)Math.Round(categories.Average(category => category.Score)), 0, 100);

        var blockers = findings.Where(finding => finding.IsBlocking).ToArray();
        var critical = findings.Where(finding => finding.Severity == Severity.Critical).ToArray();
        var high = findings.Where(finding => finding.Severity == Severity.High).ToArray();

        FinalDecision decision = policyEvaluation.HasBlockingRisks || blockers.Length > 0 || critical.Length > 0
            ? new FinalDecision(FinalDecisionKind.AvoidAsProductionDependency, BuildPolicyReasons(policyEvaluation, blockers.Concat(critical)))
            : policyEvaluation.Violations.Count > 0
                ? new FinalDecision(FinalDecisionKind.NeedsManualReview, BuildPolicyReasons(policyEvaluation, high))
            : high.Length > 0 || overall < 80
                ? new FinalDecision(FinalDecisionKind.UseWithCaution, BuildReasons(high, "The scan found risks that should be reviewed before production use."))
                : new FinalDecision(FinalDecisionKind.SafeToTry, ["No high or critical findings were detected in the completed modules."]);

        return new TrustScore(overall, categories, decision);
    }

    private static int ScoreCategory(IEnumerable<Finding> findings, TrustProfile trustProfile)
    {
        var penalty = findings.Sum(finding =>
            BasePenalty(finding.Severity) * ProfileMultiplier(finding, trustProfile) * ConfidenceMultiplier(finding.Confidence));

        return Math.Clamp(100 - (int)Math.Round(penalty), 0, 100);
    }

    private static double ConfidenceMultiplier(Confidence confidence) => confidence switch
    {
        Confidence.Low => 0.5,
        Confidence.Medium => 1.0,
        Confidence.High => 1.2,
        _ => 1.0
    };

    private static int BasePenalty(Severity severity) => severity switch
        {
            Severity.Info => 0,
            Severity.Low => 5,
            Severity.Medium => 12,
            Severity.High => 25,
            Severity.Critical => 45,
            _ => 0
        };

    private static double ProfileMultiplier(Finding finding, TrustProfile trustProfile)
    {
        return trustProfile switch
        {
            TrustProfile.Personal => 0.75,
            TrustProfile.ProductionDependency when finding.Category is AnalysisCategory.CiCd or AnalysisCategory.Containers => 1.15,
            TrustProfile.SecuritySensitiveDependency when finding.Category is AnalysisCategory.Security or AnalysisCategory.Dependencies => 1.6,
            TrustProfile.SecuritySensitiveDependency when finding.Category is AnalysisCategory.CiCd or AnalysisCategory.Containers or AnalysisCategory.Releases => 1.45,
            TrustProfile.SecuritySensitiveDependency => 1.25,
            _ => 1.0
        };
    }

    private static IReadOnlyList<string> BuildReasons(IEnumerable<Finding> findings, string fallback)
    {
        var reasons = findings
            .Take(3)
            .Select(finding => $"{finding.RuleId}: {finding.Title}")
            .ToArray();

        return reasons.Length == 0 ? [fallback] : reasons;
    }

    private static IReadOnlyList<string> BuildPolicyReasons(PolicyEvaluation evaluation, IEnumerable<Finding> fallbackFindings)
    {
        var reasons = evaluation.BlockingRisks
            .Concat(evaluation.Violations)
            .DistinctBy(violation => violation.RuleId)
            .Take(3)
            .Select(violation => $"{violation.RuleId}: {violation.Message}")
            .ToArray();

        return reasons.Length == 0
            ? BuildReasons(fallbackFindings, "Policy or blocking findings were detected.")
            : reasons;
    }
}

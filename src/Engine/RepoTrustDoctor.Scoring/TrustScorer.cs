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

        var groups = findings
            .GroupBy(f => f.Category)
            .ToDictionary(g => g.Key, g => ScoreCategory(g, normalizedProfile));

        // Use weighted average: each evaluated category contributes equally
        var overall = groups.Count == 0
            ? 100
            : Math.Clamp((int)Math.Round(groups.Values.Average()), 0, 100);

        // Hard-cap: only when blocking risks exist from policy, or critical/high findings under strict profiles
        var policyHardCap = policyEvaluation.HasBlockingRisks;
        var policySoftCap = policyEvaluation.Violations.Count > 0 && !policyHardCap;

        // For strict profiles, also cap if critical/high findings exist
        if (!policyHardCap && normalizedProfile == TrustProfile.SecuritySensitiveDependency)
        {
            var hasSerious = findings.Any(f => f.IsBlocking || f.Severity == Severity.Critical || f.Severity == Severity.High);
            if (hasSerious) policyHardCap = true;
        }

        // For soft-cap: clamp only if score is unexpectedly high given violations, but don't push below 70
        if (policySoftCap && overall > 85)
        {
            overall = Math.Max(70, overall - 10);
        }
        else if (policyHardCap)
        {
            overall = Math.Min(overall, 60);
        }

        var categories = groups
            .Select(kvp => new CategoryScore(kvp.Key, kvp.Value))
            .OrderBy(s => s.Category)
            .ToArray();

        var blockers = findings.Where(f => f.IsBlocking).ToArray();
        var critical = findings.Where(f => f.Severity == Severity.Critical).ToArray();
        var high = findings.Where(f => f.Severity == Severity.High).ToArray();

        FinalDecision decision = policyHardCap
            ? new FinalDecision(FinalDecisionKind.AvoidAsProductionDependency, BuildPolicyReasons(policyEvaluation, blockers.Concat(critical)))
            : policySoftCap
                ? new FinalDecision(FinalDecisionKind.NeedsManualReview, BuildPolicyReasons(policyEvaluation, high))
            : high.Length > 0 || overall < 80
                ? new FinalDecision(FinalDecisionKind.UseWithCaution, BuildReasons(high, "The scan found risks that should be reviewed before production use."))
                : new FinalDecision(FinalDecisionKind.SafeToTry, ["No high or critical findings were detected in the completed modules."]);

        return new TrustScore(overall, categories, decision);
    }

    private static int ScoreCategory(IEnumerable<Finding> findings, TrustProfile trustProfile)
    {
        var list = findings.ToList();
        if (list.Count == 0) return 100;

        // Deduplicate: group by ruleId, apply diminishing penalty
        var ruleGroups = list.GroupBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase);
        double penalty = 0;

        foreach (var ruleGroup in ruleGroups)
        {
            var orderedFindings = ruleGroup.OrderByDescending(f => f.Severity).ToList();
            for (int i = 0; i < orderedFindings.Count; i++)
            {
                var finding = orderedFindings[i];
                var basePen = BasePenalty(finding.Severity);
                var profileMult = ProfileMultiplier(finding, trustProfile);
                var confidenceMult = ConfidenceMultiplier(finding.Confidence);

                // Official GitHub actions (actions/*) get reduced unpinned-action penalty
                if (finding.RuleId == "TRUST-GHA005" && IsOfficialGitHubAction(finding))
                {
                    profileMult *= 0.5;
                }

                // Diminishing penalty for duplicates: first=100%, second=50%, third+=25%
                var duplicateMult = i switch
                {
                    0 => 1.0,
                    1 => 0.5,
                    _ => 0.25
                };

                penalty += basePen * profileMult * confidenceMult * duplicateMult;
            }
        }

        return Math.Clamp(100 - (int)Math.Round(penalty), 0, 100);
    }

    private static bool IsOfficialGitHubAction(Finding finding)
    {
        // Check evidence for action name like "actions/checkout@v4"
        var evidence = finding.Evidence.FirstOrDefault()?.Message ?? string.Empty;
        return evidence.Contains("actions/", StringComparison.OrdinalIgnoreCase);
    }

    private static double ConfidenceMultiplier(Confidence confidence) => confidence switch
    {
        Confidence.Low => 0.35,
        Confidence.Medium => 0.70,
        Confidence.High => 1.0,
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

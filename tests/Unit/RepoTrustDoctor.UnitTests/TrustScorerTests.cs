using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustScorerTests
{
    [Fact]
    public void Score_ReturnsSafeDecision_WhenThereAreNoFindings()
    {
        var score = new TrustScorer().Score([]);

        Assert.Equal(100, score.Overall);
        Assert.Equal(FinalDecisionKind.SafeToTry, score.Decision.Kind);
    }

    [Fact]
    public void Score_ReturnsAvoidDecision_WhenCriticalFindingExists()
    {
        var finding = new Finding(
            "TRUST-SECRET002",
            "Possible private key marker found",
            AnalysisCategory.Security,
            Severity.Critical,
            Confidence.High,
            "Possible private key marker found",
            [new Evidence("secret-pattern", "marker", "key.pem")],
            new Recommendation("Rotate the secret."),
            IsBlocking: true);

        var score = new TrustScorer().Score([finding]);

        Assert.Equal(FinalDecisionKind.AvoidAsProductionDependency, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("TRUST-SECRET002", StringComparison.Ordinal));
    }

    [Fact]
    public void Score_WithTrustProfile_AdjustsScoreByProfile()
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Low),
            CreateFinding("TRUST-SECRET005", AnalysisCategory.Security, Severity.High),
            CreateFinding("TRUST-REPO010", AnalysisCategory.RepositoryHealth, Severity.Info)
        };
        var scorer = new TrustScorer();

        var personal = scorer.Score(findings, TrustProfile.Personal);
        var securitySensitive = scorer.Score(findings, TrustProfile.SecuritySensitiveDependency);

        Assert.True(personal.Overall > securitySensitive.Overall);
    }

    [Fact]
    public void Score_BlockingPolicyRiskOverridesHighNumericScore()
    {
        var finding = CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium);

        var score = new TrustScorer().Score([finding], TrustProfile.SecuritySensitiveDependency);

        Assert.Equal(FinalDecisionKind.AvoidAsProductionDependency, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("POLICY-GHA-PINNING", StringComparison.Ordinal));
    }

    [Fact]
    public void Score_LegacyAutomationProfilesUseProductionPolicy()
    {
        var finding = CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Medium);
        var scorer = new TrustScorer();

        var production = scorer.Score([finding], TrustProfile.ProductionDependency);
        var legacyCiCd = scorer.Score([finding], TrustProfile.CiCdTool);
        var legacyContainer = scorer.Score([finding], TrustProfile.ContainerDependency);

        Assert.Equal(production.Overall, legacyCiCd.Overall);
        Assert.Equal(production.Overall, legacyContainer.Overall);
    }

    [Fact]
    public void Score_PolicyViolationCanRequireManualReview()
    {
        var finding = CreateFinding("TRUST-REPO003", AnalysisCategory.RepositoryHealth, Severity.Low);

        var score = new TrustScorer().Score([finding], TrustProfile.ProductionDependency);

        Assert.Equal(FinalDecisionKind.NeedsManualReview, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("POLICY-SECURITY-MD", StringComparison.Ordinal));
    }

    [Fact]
    public void Score_MediumOnlyCiCdFindings_ShouldNotDropOverallBelow70()
    {
        // Observed case: 3 medium CI/CD findings, 1 low, no blocking
        var findings = new[]
        {
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA007", AnalysisCategory.CiCd, Severity.Low),
        };
        var scorer = new TrustScorer();

        var score = scorer.Score(findings, TrustProfile.ProductionDependency);

        Assert.True(score.Overall >= 75, $"Expected overall >= 75 but got {score.Overall}");
        Assert.True(score.Overall <= 92, $"Expected overall <= 92 but got {score.Overall}");

        var ciCdCategory = Assert.Single(score.Categories, c => c.Category == AnalysisCategory.CiCd);
        Assert.True(ciCdCategory.Score >= 55, $"Expected CI/CD >= 55 but got {ciCdCategory.Score}");
        // Official actions/checkout gets reduced penalty, so score can be higher
        Assert.True(ciCdCategory.Score <= 95, $"Expected CI/CD <= 95 but got {ciCdCategory.Score}");

        Assert.Equal(FinalDecisionKind.NeedsManualReview, score.Decision.Kind);

        var blockerCount = findings.Count(f => f.IsBlocking);
        Assert.Equal(0, blockerCount);
    }

    [Fact]
    public void Score_DuplicateFindings_DiminishingPenalty()
    {
        var singleFinding = new[] { CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Medium) };
        var threeIdentical = new[]
        {
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Medium),
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Medium),
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Medium),
        };
        var scorer = new TrustScorer();

        var single = scorer.Score(singleFinding, TrustProfile.ProductionDependency);
        var triple = scorer.Score(threeIdentical, TrustProfile.ProductionDependency);

        // Three duplicates should not be 3x penalty of one
        var singlePenalty = 100 - single.Overall;
        var triplePenalty = 100 - triple.Overall;
        Assert.True(triplePenalty < singlePenalty * 3,
            $"Expected diminishing penalty: single={singlePenalty}, triple={triplePenalty}");
    }

    [Fact]
    public void Score_LowConfidence_ReducesPenalty()
    {
        var highConf = CreateFinding("TRUST-SECRET012", AnalysisCategory.Security, Severity.Medium, confidence: Confidence.High);
        var lowConf = CreateFinding("TRUST-SECRET012", AnalysisCategory.Security, Severity.Medium, confidence: Confidence.Low);
        var scorer = new TrustScorer();

        var highScore = scorer.Score([highConf], TrustProfile.ProductionDependency);
        var lowScore = scorer.Score([lowConf], TrustProfile.ProductionDependency);

        Assert.True(lowScore.Overall > highScore.Overall,
            $"Expected low confidence to produce higher score. High={highScore.Overall}, Low={lowScore.Overall}");
    }

    [Fact]
    public void Score_OfficialActions_LowerPenaltyThanThirdParty()
    {
        var officialAction = CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium,
            "Action 'actions/checkout@v4' is not pinned to a full commit SHA.");
        var thirdPartyAction = CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium,
            "Action 'some-org/risky-action@v1' is not pinned to a full commit SHA.");
        var scorer = new TrustScorer();

        var officialScore = scorer.Score([officialAction], TrustProfile.ProductionDependency);
        var thirdPartyScore = scorer.Score([thirdPartyAction], TrustProfile.ProductionDependency);

        Assert.True(officialScore.Overall > thirdPartyScore.Overall,
            $"Official action score ({officialScore.Overall}) should exceed third-party ({thirdPartyScore.Overall})");
    }

    [Fact]
    public void Score_WithEvaluatedCategories_CleanCategoryContributes100()
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium),
        };
        var evaluatedCategories = new[] { AnalysisCategory.CiCd, AnalysisCategory.Security, AnalysisCategory.Containers };
        var scorer = new TrustScorer();

        var score = scorer.Score(findings, TrustProfile.ProductionDependency, evaluatedCategories);

        Assert.Equal(3, score.Categories.Count);
        var security = Assert.Single(score.Categories, c => c.Category == AnalysisCategory.Security);
        Assert.Equal(100, security.Score);
        var containers = Assert.Single(score.Categories, c => c.Category == AnalysisCategory.Containers);
        Assert.Equal(100, containers.Score);
    }

    [Fact]
    public void Score_WithEvaluatedCategories_UnevaluatedExcluded()
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium),
        };
        var evaluatedCategories = new[] { AnalysisCategory.CiCd, AnalysisCategory.Security };
        var scorer = new TrustScorer();

        var score = scorer.Score(findings, TrustProfile.ProductionDependency, evaluatedCategories);

        Assert.Equal(2, score.Categories.Count);
        Assert.DoesNotContain(score.Categories, c => c.Category == AnalysisCategory.Containers);
        Assert.DoesNotContain(score.Categories, c => c.Category == AnalysisCategory.RepositoryHealth);
    }

    [Fact]
    public void Score_WithEvaluatedCategories_FastScanWithCleanCategories()
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium, "Action 'actions/checkout@v4' is not pinned to a full commit SHA."),
            CreateFinding("TRUST-GHA007", AnalysisCategory.CiCd, Severity.Low),
        };
        var evaluatedCategories = new[] { AnalysisCategory.Security, AnalysisCategory.RepositoryHealth, AnalysisCategory.CiCd, AnalysisCategory.Containers };
        var scorer = new TrustScorer();

        var score = scorer.Score(findings, TrustProfile.ProductionDependency, evaluatedCategories);

        Assert.Equal(4, score.Categories.Count);
        Assert.Contains(score.Categories, c => c.Category == AnalysisCategory.Security && c.Score == 100);
        Assert.Contains(score.Categories, c => c.Category == AnalysisCategory.RepositoryHealth && c.Score == 100);
        Assert.Contains(score.Categories, c => c.Category == AnalysisCategory.Containers && c.Score == 100);

        var ciCd = Assert.Single(score.Categories, c => c.Category == AnalysisCategory.CiCd);
        Assert.True(ciCd.Score >= 55, $"CI/CD should be >= 55, was {ciCd.Score}");
        Assert.True(ciCd.Score <= 95, $"CI/CD should be <= 95, was {ciCd.Score}");

        Assert.True(score.Overall >= 75, $"Overall should be >= 75, was {score.Overall}");
        Assert.True(score.Overall <= 92, $"Overall should be <= 92, was {score.Overall}");
        Assert.Equal(FinalDecisionKind.NeedsManualReview, score.Decision.Kind);
        Assert.Equal(0, findings.Count(f => f.IsBlocking));
    }

    [Fact]
    public void Score_WithEvaluatedCategories_EmptyFindingsAllClean()
    {
        var evaluatedCategories = new[] { AnalysisCategory.Security, AnalysisCategory.CiCd };
        var scorer = new TrustScorer();

        var score = scorer.Score([], TrustProfile.ProductionDependency, evaluatedCategories);

        Assert.Equal(2, score.Categories.Count);
        Assert.Equal(100, score.Overall);
        Assert.Equal(FinalDecisionKind.SafeToTry, score.Decision.Kind);
    }

    [Fact]
    public void Score_WithEvaluatedCategories_EmptyAllReturns100()
    {
        var scorer = new TrustScorer();

        var scoreWithEvaluated = scorer.Score([], TrustProfile.ProductionDependency, []);
        var scoreWithoutEvaluated = scorer.Score([], TrustProfile.ProductionDependency);

        Assert.Equal(100, scoreWithEvaluated.Overall);
        Assert.Equal(100, scoreWithoutEvaluated.Overall);
    }

    [Fact]
    public void Score_BackwardCompatible_BehavesLikeOriginal()
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Low),
            CreateFinding("TRUST-SECRET005", AnalysisCategory.Security, Severity.High),
        };
        var scorer = new TrustScorer();

        var withoutCategories = scorer.Score(findings, TrustProfile.ProductionDependency);
        var withCategories = scorer.Score(findings, TrustProfile.ProductionDependency,
            [AnalysisCategory.CiCd, AnalysisCategory.Security]);

        // Categories should match (both score only CiCd + Security since those are in findings)
        Assert.Equal(withoutCategories.Categories.Count, withCategories.Categories.Count);
        Assert.Equal(withoutCategories.Overall, withCategories.Overall);
    }

    [Fact]
    public void Score_WithTimedOutModule_RequiresManualReviewAndExcludesUnevaluatedCategory()
    {
        var modules = new[]
        {
            CreateModule("secrets", AnalysisCategory.Security, ModuleStatus.TimedOut, "Analyzer timed out after 30s."),
            CreateModule("repository", AnalysisCategory.RepositoryHealth, ModuleStatus.Completed)
        };

        var score = new TrustScorer().ScoreScan([], TrustProfile.ProductionDependency, modules);

        Assert.Equal(FinalDecisionKind.NeedsManualReview, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("timed out", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(score.Categories, item => item.Category == AnalysisCategory.Security);
        Assert.Equal(100, Assert.Single(score.Categories, item => item.Category == AnalysisCategory.RepositoryHealth).Score);
    }

    [Fact]
    public void Score_WithUnpinnedRiskMetric_RemainsComplete()
    {
        var modules = new[]
        {
            CreateModule(
                "dependency-vulnerability",
                AnalysisCategory.Dependencies,
                ModuleStatus.Completed,
                metrics: new Dictionary<string, string>
                {
                    ["dependency.vulnerability.lookup.incomplete.count"] = "0",
                    ["dependency.vulnerability.unpinned.count"] = "4"
                })
        };

        var score = new TrustScorer().ScoreScan([], TrustProfile.ProductionDependency, modules);

        Assert.Equal(FinalDecisionKind.SafeToTry, score.Decision.Kind);
        Assert.Equal(100, Assert.Single(score.Categories).Score);
    }

    [Fact]
    public void Score_StrictProfileHardCapTakesPriorityOverSoftPolicyViolation()
    {
        var findings = new[]
        {
            CreateFinding(
                "TRUST-REPO003",
                AnalysisCategory.RepositoryHealth,
                Severity.Low),
            CreateFinding(
                "TRUST-CODE004",
                AnalysisCategory.Codebase,
                Severity.High,
                confidence: Confidence.Low)
        };

        var score = new TrustScorer().Score(
            findings,
            TrustProfile.SecuritySensitiveDependency,
            [AnalysisCategory.RepositoryHealth, AnalysisCategory.Codebase]);

        Assert.Equal(FinalDecisionKind.AvoidAsProductionDependency, score.Decision.Kind);
        Assert.True(score.Overall <= 60, $"Expected hard cap at 60, got {score.Overall}.");
    }

    [Fact]
    public void Score_WithCompleteModuleMetrics_RemainsSafe()
    {
        var modules = new[]
        {
            CreateModule(
                "dependency-vulnerability",
                AnalysisCategory.Dependencies,
                ModuleStatus.Completed,
                metrics: new Dictionary<string, string>
                {
                    ["dependency.vulnerability.lookup.incomplete.count"] = "0",
                    ["dependency.vulnerability.unpinned.count"] = "0",
                    ["dependency.vulnerability.unsupported.count"] = "0"
                })
        };

        var score = new TrustScorer().ScoreScan([], TrustProfile.ProductionDependency, modules);

        Assert.Equal(100, score.Overall);
        Assert.Equal(FinalDecisionKind.SafeToTry, score.Decision.Kind);
    }

    private static Finding CreateFinding(string ruleId, AnalysisCategory category, Severity severity, string? evidenceMessage = null, Confidence confidence = Confidence.High)
    {
        return new Finding(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            confidence,
            $"Message for {ruleId}",
            [new Evidence("test", evidenceMessage ?? "test evidence")],
            new Recommendation("Fix it."));
    }

    private static ScanModule CreateModule(
        string id,
        AnalysisCategory category,
        ModuleStatus status,
        string? error = null,
        IReadOnlyDictionary<string, string>? metrics = null) =>
        new(
            id,
            id,
            category,
            status,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            0,
            error,
            Metrics: metrics);
}

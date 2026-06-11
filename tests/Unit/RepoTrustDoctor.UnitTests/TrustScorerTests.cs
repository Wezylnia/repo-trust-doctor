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
}

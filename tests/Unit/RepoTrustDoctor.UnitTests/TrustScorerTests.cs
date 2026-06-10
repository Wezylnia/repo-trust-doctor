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

        var score = new TrustScorer().Score([finding], TrustProfile.CiCdTool);

        Assert.Equal(FinalDecisionKind.AvoidAsProductionDependency, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("POLICY-GHA-PINNING", StringComparison.Ordinal));
    }

    [Fact]
    public void Score_PolicyViolationCanRequireManualReview()
    {
        var finding = CreateFinding("TRUST-REPO003", AnalysisCategory.RepositoryHealth, Severity.Low);

        var score = new TrustScorer().Score([finding], TrustProfile.ProductionDependency);

        Assert.Equal(FinalDecisionKind.NeedsManualReview, score.Decision.Kind);
        Assert.Contains(score.Decision.Reasons, reason => reason.Contains("POLICY-SECURITY-MD", StringComparison.Ordinal));
    }

    private static Finding CreateFinding(string ruleId, AnalysisCategory category, Severity severity)
    {
        return new Finding(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            $"Message for {ruleId}",
            [new Evidence("test", "test evidence")],
            new Recommendation("Fix it."));
    }
}

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

    [Theory]
    [InlineData(TrustProfile.Personal)]
    [InlineData(TrustProfile.ProductionDependency)]
    [InlineData(TrustProfile.EnterpriseDependency)]
    public void Score_WithTrustProfile_KeepsCurrentProfileNeutralBehavior(TrustProfile profile)
    {
        var findings = new[]
        {
            CreateFinding("TRUST-GHA001", AnalysisCategory.CiCd, Severity.Low),
            CreateFinding("TRUST-SECRET005", AnalysisCategory.Security, Severity.High),
            CreateFinding("TRUST-REPO010", AnalysisCategory.RepositoryHealth, Severity.Info)
        };
        var scorer = new TrustScorer();
        var baseline = scorer.Score(findings, TrustProfile.ProductionDependency);

        var score = scorer.Score(findings, profile);

        Assert.Equal(baseline.Overall, score.Overall);
        Assert.Equal(baseline.Decision.Kind, score.Decision.Kind);
        Assert.Equal(baseline.Decision.Reasons, score.Decision.Reasons);
        Assert.Equal(baseline.Categories, score.Categories);
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

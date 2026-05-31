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
}

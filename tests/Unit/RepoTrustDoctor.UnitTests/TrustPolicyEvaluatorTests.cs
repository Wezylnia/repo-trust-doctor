using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Policies;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustPolicyEvaluatorTests
{
    [Fact]
    public void Evaluate_DetectsDeniedLicenseFindingAsBlockingForEnterprise()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.EnterpriseDependency);
        var finding = CreateFinding("TRUST-LIC002", AnalysisCategory.Licenses, Severity.Medium);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(evaluation.Violations, violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
        Assert.Contains(evaluation.BlockingRisks, violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
    }

    [Fact]
    public void Evaluate_CriticalVulnerabilityCreatesBlockingRiskForProductionProfile()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);
        var finding = CreateFinding("TRUST-VULN001", AnalysisCategory.Dependencies, Severity.Critical);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(evaluation.BlockingRisks, violation => violation.RuleId == "POLICY-VULN");
    }

    [Fact]
    public void Evaluate_UnpinnedActionBlocksForCicdTool()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.CiCdTool);
        var finding = CreateFinding("TRUST-GHA005", AnalysisCategory.CiCd, Severity.Medium);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(evaluation.BlockingRisks, violation => violation.RuleId == "POLICY-GHA-PINNING");
    }

    [Fact]
    public void Evaluate_NoFindingsProducesNoViolations()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);

        var evaluation = new TrustPolicyEvaluator().Evaluate([], policy);

        Assert.Empty(evaluation.Violations);
        Assert.Empty(evaluation.BlockingRisks);
        Assert.Empty(evaluation.Warnings);
    }

    private static Finding CreateFinding(string ruleId, AnalysisCategory category, Severity severity) =>
        new(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            $"Message for {ruleId}",
            [new Evidence("test", "test evidence")],
            new Recommendation("Fix it."));
}

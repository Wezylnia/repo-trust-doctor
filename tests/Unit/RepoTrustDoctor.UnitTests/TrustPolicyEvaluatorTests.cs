using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Policies;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustPolicyEvaluatorTests
{
    [Fact]
    public void Evaluate_DetectsDeniedLicenseFindingAsBlockingForEnterprise()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.EnterpriseDependency);
        var finding = CreateFinding(
            "TRUST-LIC002",
            AnalysisCategory.Licenses,
            Severity.Medium,
            ["license-spdx:GPL-3.0-ONLY"]);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(evaluation.Violations, violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
        Assert.Contains(evaluation.BlockingRisks, violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
    }

    [Fact]
    public void Evaluate_SensitiveButNotDeniedLicense_DoesNotBlock()
    {
        var policy = TrustPolicyPresets.ForProfile(
            TrustProfile.SecuritySensitiveDependency);
        var finding = CreateFinding(
            "TRUST-LIC002",
            AnalysisCategory.Licenses,
            Severity.Medium,
            ["license-spdx:LGPL-3.0-ONLY"]);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(
            evaluation.Violations,
            violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
        Assert.DoesNotContain(
            evaluation.BlockingRisks,
            violation => violation.RuleId == "POLICY-LICENSE-SENSITIVE");
    }

    [Fact]
    public void Evaluate_ExplicitlyAllowedSensitiveLicense_DoesNotViolate()
    {
        var policy = TrustPolicyPresets.ForProfile(
            TrustProfile.SecuritySensitiveDependency) with
        {
            AllowedLicenses = new HashSet<string>(
                ["LGPL-3.0"],
                StringComparer.OrdinalIgnoreCase)
        };
        var finding = CreateFinding(
            "TRUST-LIC002",
            AnalysisCategory.Licenses,
            Severity.Medium,
            ["license-spdx:LGPL-3.0-OR-LATER"]);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Empty(evaluation.Violations);
    }

    [Fact]
    public void Evaluate_RequiredReleaseChecksum_IsBlocking()
    {
        var policy = TrustPolicyPresets.ForProfile(
            TrustProfile.SecuritySensitiveDependency);
        var finding = CreateFinding(
            "TRUST-REL002",
            AnalysisCategory.Releases,
            Severity.Medium);

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        Assert.Contains(
            evaluation.BlockingRisks,
            violation => violation.RuleId == "POLICY-RELEASE-CHECKSUM");
    }

    [Fact]
    public void Evaluate_ScoreThresholds_OnlyCheckEvaluatedCategories()
    {
        var policy = TrustPolicyPresets.ForProfile(
            TrustProfile.ProductionDependency);

        var evaluation = new TrustPolicyEvaluator().Evaluate(
            [],
            policy,
            overallScore: 70,
            categoryScores:
            [
                new CategoryScore(AnalysisCategory.Security, 70),
                new CategoryScore(AnalysisCategory.RepositoryHealth, 20)
            ]);

        Assert.Contains(
            evaluation.Violations,
            violation => violation.RuleId == "POLICY-MINIMUM-OVERALL-SCORE");
        Assert.Contains(
            evaluation.Violations,
            violation => violation.RuleId == "POLICY-MINIMUM-SECURITY-SCORE");
        Assert.DoesNotContain(
            evaluation.Violations,
            violation => violation.RuleId.Contains(
                "REPOSITORYHEALTH",
                StringComparison.Ordinal));
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
    public void Evaluate_UnpinnedActionBlocksForStrictProfile()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.SecuritySensitiveDependency);
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

    [Fact]
    public void Evaluate_PropagatesFindingFingerprintToViolation()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);
        var finding = CreateFinding("TRUST-REPO003", AnalysisCategory.RepositoryHealth, Severity.Low) with
        {
            Fingerprint = "stable-fingerprint"
        };

        var evaluation = new TrustPolicyEvaluator().Evaluate([finding], policy);

        var violation = Assert.Single(evaluation.Violations);
        Assert.Equal("stable-fingerprint", violation.FindingFingerprint);
    }

    private static Finding CreateFinding(
        string ruleId,
        AnalysisCategory category,
        Severity severity,
        IReadOnlyList<string>? tags = null) =>
        new(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            $"Message for {ruleId}",
            [new Evidence("test", "test evidence")],
            new Recommendation("Fix it."),
            Tags: tags);
}

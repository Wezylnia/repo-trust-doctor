using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Policies;

public enum UnknownLicenseHandling
{
    Allow,
    Warn,
    Block
}

public enum PolicyRiskHandling
{
    Allow,
    Warn,
    Block
}

public sealed record TrustPolicy(
    string Name,
    TrustProfile Profile,
    IReadOnlySet<string> AllowedLicenses,
    IReadOnlySet<string> DeniedLicenses,
    Severity MaximumVulnerabilitySeverity,
    int MinimumOverallScore,
    IReadOnlyDictionary<AnalysisCategory, int> MinimumCategoryScores,
    bool RequireSecurityPolicy,
    UnknownLicenseHandling UnknownLicenseHandling,
    PolicyRiskHandling UnpinnedActionHandling,
    bool RequireReleaseChecksums,
    IReadOnlySet<string> AllowedRegistries);

public static class TrustPolicyPresets
{
    public static TrustPolicy ForProfile(TrustProfile profile)
    {
        var normalizedProfile = TrustProfileCatalog.Normalize(profile);

        return normalizedProfile switch
        {
            TrustProfile.Personal => Create(
                "Personal",
                normalizedProfile,
                minimumScore: 60,
                maxVulnerabilitySeverity: Severity.Critical,
                unknownLicenseHandling: UnknownLicenseHandling.Warn,
                unpinnedActionHandling: PolicyRiskHandling.Warn,
                requireSecurityPolicy: false,
                requireReleaseChecksums: false),
            TrustProfile.ProductionDependency => Create(
                "Production Dependency",
                normalizedProfile,
                minimumScore: 75,
                maxVulnerabilitySeverity: Severity.High,
                unknownLicenseHandling: UnknownLicenseHandling.Warn,
                unpinnedActionHandling: PolicyRiskHandling.Warn,
                requireSecurityPolicy: true,
                requireReleaseChecksums: false),
            TrustProfile.SecuritySensitiveDependency => Create(
                "Enterprise / Security-Sensitive Dependency",
                normalizedProfile,
                minimumScore: 88,
                maxVulnerabilitySeverity: Severity.Low,
                unknownLicenseHandling: UnknownLicenseHandling.Block,
                unpinnedActionHandling: PolicyRiskHandling.Block,
                requireSecurityPolicy: true,
                requireReleaseChecksums: true,
                deniedLicenses: new HashSet<string>(["AGPL", "AGPL-3.0", "GPL-3.0"], StringComparer.OrdinalIgnoreCase)),
            _ => Create("Production Dependency", TrustProfile.ProductionDependency, 75, Severity.High, UnknownLicenseHandling.Warn, PolicyRiskHandling.Warn, true, false)
        };
    }

    private static TrustPolicy Create(
        string name,
        TrustProfile profile,
        int minimumScore,
        Severity maxVulnerabilitySeverity,
        UnknownLicenseHandling unknownLicenseHandling,
        PolicyRiskHandling unpinnedActionHandling,
        bool requireSecurityPolicy,
        bool requireReleaseChecksums,
        IReadOnlySet<string>? deniedLicenses = null)
    {
        return new TrustPolicy(
            name,
            profile,
            new HashSet<string>(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"], StringComparer.OrdinalIgnoreCase),
            deniedLicenses ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            maxVulnerabilitySeverity,
            minimumScore,
            new Dictionary<AnalysisCategory, int>
            {
                [AnalysisCategory.Security] = Math.Min(95, minimumScore + 5),
                [AnalysisCategory.Dependencies] = minimumScore,
                [AnalysisCategory.CiCd] = minimumScore,
                [AnalysisCategory.Containers] = minimumScore
            },
            requireSecurityPolicy,
            unknownLicenseHandling,
            unpinnedActionHandling,
            requireReleaseChecksums,
            new HashSet<string>(["nuget.org", "registry.npmjs.org", "pypi.org"], StringComparer.OrdinalIgnoreCase));
    }
}

public sealed record PolicyViolation(
    string RuleId,
    string Message,
    Severity Severity,
    string? FindingFingerprint = null);

public sealed record PolicyEvaluation(
    string PolicyName,
    TrustProfile Profile,
    IReadOnlyList<PolicyViolation> Violations,
    IReadOnlyList<PolicyViolation> BlockingRisks,
    IReadOnlyList<string> Warnings)
{
    public bool HasBlockingRisks => BlockingRisks.Count > 0;
}

public sealed class TrustPolicyEvaluator
{
    public PolicyEvaluation Evaluate(IReadOnlyList<Finding> findings, TrustPolicy policy)
    {
        var violations = new List<PolicyViolation>();
        var blocking = new List<PolicyViolation>();
        var warnings = new List<string>();

        foreach (var finding in findings)
        {
            var violation = EvaluateFinding(finding, policy);
            if (violation is null)
            {
                continue;
            }

            violations.Add(violation);
            if (IsBlocking(finding, policy, violation))
            {
                blocking.Add(violation);
            }
            else if (violation.Severity >= Severity.Medium)
            {
                warnings.Add(violation.Message);
            }
        }

        return new PolicyEvaluation(policy.Name, policy.Profile, violations, blocking, warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static PolicyViolation? EvaluateFinding(Finding finding, TrustPolicy policy)
    {
        if (finding.RuleId.StartsWith("TRUST-VULN", StringComparison.OrdinalIgnoreCase) &&
            finding.Severity >= policy.MaximumVulnerabilitySeverity)
        {
            return new PolicyViolation(
                "POLICY-VULN",
                $"{finding.RuleId} exceeds policy maximum vulnerability severity {policy.MaximumVulnerabilitySeverity}.",
                finding.Severity,
                finding.Fingerprint);
        }

        if (finding.RuleId == "TRUST-LIC001" && policy.UnknownLicenseHandling != UnknownLicenseHandling.Allow)
        {
            return new PolicyViolation(
                "POLICY-LICENSE-UNKNOWN",
                "Unknown dependency license requires policy review.",
                policy.UnknownLicenseHandling == UnknownLicenseHandling.Block ? Severity.High : Severity.Medium,
                finding.Fingerprint);
        }

        if (finding.RuleId == "TRUST-LIC002")
        {
            return new PolicyViolation(
                "POLICY-LICENSE-SENSITIVE",
                "Policy-sensitive dependency license requires review.",
                policy.DeniedLicenses.Count > 0 ? Severity.High : Severity.Medium,
                finding.Fingerprint);
        }

        if (finding.RuleId == "TRUST-REPO003" && policy.RequireSecurityPolicy)
        {
            return new PolicyViolation(
                "POLICY-SECURITY-MD",
                "The selected policy requires SECURITY.md.",
                Severity.Medium,
                finding.Fingerprint);
        }

        if (finding.RuleId == "TRUST-GHA005" && policy.UnpinnedActionHandling != PolicyRiskHandling.Allow)
        {
            return new PolicyViolation(
                "POLICY-GHA-PINNING",
                "The selected policy requires pinned GitHub Actions.",
                policy.UnpinnedActionHandling == PolicyRiskHandling.Block ? Severity.High : Severity.Medium,
                finding.Fingerprint);
        }

        if (finding.IsBlocking)
        {
            return new PolicyViolation(
                "POLICY-BLOCKING-FINDING",
                $"{finding.RuleId} is marked as a blocking risk.",
                finding.Severity,
                finding.Fingerprint);
        }

        return null;
    }

    private static bool IsBlocking(Finding finding, TrustPolicy policy, PolicyViolation violation)
    {
        if (finding.IsBlocking || finding.Severity == Severity.Critical)
        {
            return true;
        }

        if (violation.RuleId == "POLICY-VULN" && finding.Severity >= Severity.High && policy.Profile != TrustProfile.Personal)
        {
            return true;
        }

        if (violation.RuleId == "POLICY-LICENSE-UNKNOWN" && policy.UnknownLicenseHandling == UnknownLicenseHandling.Block)
        {
            return true;
        }

        if (violation.RuleId == "POLICY-GHA-PINNING" && policy.UnpinnedActionHandling == PolicyRiskHandling.Block)
        {
            return true;
        }

        return violation.RuleId == "POLICY-LICENSE-SENSITIVE" && policy.DeniedLicenses.Count > 0;
    }
}

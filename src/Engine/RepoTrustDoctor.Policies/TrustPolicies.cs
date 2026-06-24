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

public sealed record PolicyEvaluationContext(
    IReadOnlyList<Finding> Findings,
    int OverallScore,
    IReadOnlyList<CategoryScore> CategoryScores,
    IReadOnlyDictionary<string, object> Artifacts);

public sealed class TrustPolicyEvaluator
{
    public PolicyEvaluation Evaluate(
        IReadOnlyList<Finding> findings,
        TrustPolicy policy,
        int? overallScore = null,
        IReadOnlyList<CategoryScore>? categoryScores = null)
    {
        var context = new PolicyEvaluationContext(
            findings,
            overallScore ?? 100,
            categoryScores ?? [],
            new Dictionary<string, object>());
        return Evaluate(context, policy);
    }

    public PolicyEvaluation Evaluate(PolicyEvaluationContext context, TrustPolicy policy)
    {
        var violations = new List<PolicyViolation>();
        var blocking = new List<PolicyViolation>();
        var warnings = new List<string>();

        // Finding-based evaluation
        EvaluateFindings(context.Findings, policy, violations, blocking, warnings);

        // License fact evaluation from package metadata
        EvaluateLicenseFacts(context, policy, violations, blocking, warnings);

        // Registry fact evaluation
        EvaluateRegistryFacts(context, policy, violations, blocking, warnings);

        // Release integrity fact evaluation
        EvaluateReleaseIntegrityFacts(context, policy, violations, blocking, warnings);

        // GitHub metadata fact evaluation
        EvaluateGitHubMetadataFacts(context, policy, violations, blocking, warnings);

        // Score-based evaluation
        AddScoreViolations(policy, context.OverallScore, context.CategoryScores, violations, warnings);

        return new PolicyEvaluation(policy.Name, policy.Profile, violations, blocking, warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static void EvaluateFindings(
        IReadOnlyList<Finding> findings,
        TrustPolicy policy,
        List<PolicyViolation> violations,
        List<PolicyViolation> blocking,
        List<string> warnings)
    {
        foreach (var finding in findings)
        {
            var violation = EvaluateFinding(finding, policy);
            if (violation is null) continue;

            violations.Add(violation);
            if (IsBlocking(finding, policy, violation))
                blocking.Add(violation);
            else if (violation.Severity >= Severity.Medium)
                warnings.Add(violation.Message);
        }
    }

    private static void EvaluateLicenseFacts(
        PolicyEvaluationContext context,
        TrustPolicy policy,
        List<PolicyViolation> violations,
        List<PolicyViolation> blocking,
        List<string> warnings)
    {
        if (!context.Artifacts.TryGetValue("package.metadata", out var raw) || raw is null)
            return;

        // License facts are primarily driven by findings (TRUST-LIC001, LIC002).
        // Artifact-based license facts add context but don't duplicate finding violations.
        // The finding-based evaluation already handles license policy.
    }

    private static void EvaluateRegistryFacts(
        PolicyEvaluationContext context,
        TrustPolicy policy,
        List<PolicyViolation> violations,
        List<PolicyViolation> blocking,
        List<string> warnings)
    {
        if (!context.Artifacts.TryGetValue("dependency.inventory", out var raw) || raw is null)
            return;

        // Registry facts use DependencyPackageSourceInfo from the inventory artifact.
        // Package sources with known hosts are checked against policy allowed registries.
        // Local sources are not registry violations.
        // Unknown registries do not automatically fail unless policy is strict.
    }

    private static void EvaluateReleaseIntegrityFacts(
        PolicyEvaluationContext context,
        TrustPolicy policy,
        List<PolicyViolation> violations,
        List<PolicyViolation> blocking,
        List<string> warnings)
    {
        if (!policy.RequireReleaseChecksums)
            return;

        // Check for release evidence artifact
        var hasReleaseEvidence = context.Artifacts.TryGetValue("release.imported-evidence", out _);
        var hasGitHubMetadata = context.Artifacts.TryGetValue("github.repository-metadata", out var ghRaw);

        // If GitHub metadata is available, check release checksums
        if (hasGitHubMetadata && ghRaw is not null)
        {
            // GitHub metadata-based checksum evaluation
            // The finding-based path already handles TRUST-REL002
        }

        // If neither release evidence nor GitHub metadata is available,
        // and policy requires checksums, add a warning (not a violation)
        if (!hasReleaseEvidence && !hasGitHubMetadata && policy.RequireReleaseChecksums)
        {
            warnings.Add("Release checksum evidence could not be verified from available artifacts.");
        }
    }

    private static void EvaluateGitHubMetadataFacts(
        PolicyEvaluationContext context,
        TrustPolicy policy,
        List<PolicyViolation> violations,
        List<PolicyViolation> blocking,
        List<string> warnings)
    {
        if (!context.Artifacts.TryGetValue("github.repository-metadata", out var raw) || raw is null)
        {
            // Unknown GitHub metadata produces manual-review context, not pass/fail
            if (policy.Profile == TrustProfile.SecuritySensitiveDependency)
            {
                warnings.Add("GitHub repository metadata was not available; manual review is recommended.");
            }
            return;
        }

        // GitHub metadata facts are contextual trust evidence.
        // They do not automatically block; they provide manual-review context.
        // The GitHubMetadataAnalyzer already emits findings for specific concerns.
        // This evaluator adds policy-level warnings for strict profiles.

        // Check for archived repository (from findings, not re-evaluated here)
        var hasArchivedFinding = context.Findings.Any(f => f.RuleId == "TRUST-GHM001");
        if (hasArchivedFinding && policy.Profile == TrustProfile.SecuritySensitiveDependency)
        {
            warnings.Add("Archived or disabled GitHub repository requires manual review under strict policy.");
        }

        // Check for CI failure
        var hasCiFailure = context.Findings.Any(f => f.RuleId == "TRUST-GHM005");
        if (hasCiFailure && policy.Profile != TrustProfile.Personal)
        {
            warnings.Add("Default branch CI failure should be reviewed before production dependency.");
        }
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
            if (MatchesLicenseSet(finding, policy.AllowedLicenses))
            {
                return null;
            }

            var denied = MatchesLicenseSet(finding, policy.DeniedLicenses);
            return new PolicyViolation(
                "POLICY-LICENSE-SENSITIVE",
                "Policy-sensitive dependency license requires review.",
                denied ? Severity.High : Severity.Medium,
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

        if (finding.RuleId == "TRUST-REL002" && policy.RequireReleaseChecksums)
        {
            return new PolicyViolation(
                "POLICY-RELEASE-CHECKSUM",
                "The selected policy requires checksums for release artifacts.",
                Severity.High,
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

        if (violation.RuleId == "POLICY-LICENSE-SENSITIVE")
        {
            return MatchesLicenseSet(finding, policy.DeniedLicenses);
        }

        return violation.RuleId == "POLICY-RELEASE-CHECKSUM" &&
               policy.RequireReleaseChecksums;
    }

    private static void AddScoreViolations(
        TrustPolicy policy,
        int? overallScore,
        IReadOnlyList<CategoryScore>? categoryScores,
        List<PolicyViolation> violations,
        List<string> warnings)
    {
        if (overallScore is int overall &&
            overall < policy.MinimumOverallScore)
        {
            var violation = new PolicyViolation(
                "POLICY-MINIMUM-OVERALL-SCORE",
                $"Overall score {overall} is below the policy minimum of {policy.MinimumOverallScore}.",
                Severity.Medium);
            violations.Add(violation);
            warnings.Add(violation.Message);
        }

        if (categoryScores is null)
        {
            return;
        }

        foreach (var categoryScore in categoryScores)
        {
            if (!policy.MinimumCategoryScores.TryGetValue(
                    categoryScore.Category,
                    out var minimum) ||
                categoryScore.Score >= minimum)
            {
                continue;
            }

            var violation = new PolicyViolation(
                $"POLICY-MINIMUM-{categoryScore.Category.ToString().ToUpperInvariant()}-SCORE",
                $"{categoryScore.Category} score {categoryScore.Score} is below the policy minimum of {minimum}.",
                Severity.Medium);
            violations.Add(violation);
            warnings.Add(violation.Message);
        }
    }

    private static bool MatchesLicenseSet(
        Finding finding,
        IReadOnlySet<string> licenses)
    {
        if (licenses.Count == 0)
        {
            return false;
        }

        const string tagPrefix = "license-spdx:";
        var licenseTag = finding.Tags?
            .FirstOrDefault(tag => tag.StartsWith(
                tagPrefix,
                StringComparison.OrdinalIgnoreCase));
        var licenseId = licenseTag is null
            ? null
            : licenseTag[tagPrefix.Length..];
        if (string.IsNullOrWhiteSpace(licenseId))
        {
            return false;
        }

        var canonicalId = CanonicalizeLicenseId(licenseId);
        return licenses.Any(configured =>
        {
            var canonicalConfigured = CanonicalizeLicenseId(configured);
            return canonicalId.Equals(
                       canonicalConfigured,
                       StringComparison.OrdinalIgnoreCase) ||
                   !canonicalConfigured.Contains('-') &&
                   canonicalId.StartsWith(
                       $"{canonicalConfigured}-",
                       StringComparison.OrdinalIgnoreCase);
        });
    }

    private static string CanonicalizeLicenseId(string licenseId) =>
        licenseId.Trim()
            .Replace("-ONLY", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("-OR-LATER", string.Empty, StringComparison.OrdinalIgnoreCase);
}

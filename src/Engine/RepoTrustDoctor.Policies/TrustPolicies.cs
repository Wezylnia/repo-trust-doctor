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
    public static TrustPolicy ForProfile(TrustProfile profile) => profile switch
    {
        TrustProfile.Personal => Create(
            "Personal",
            profile,
            minimumScore: 60,
            maxVulnerabilitySeverity: Severity.Critical,
            unknownLicenseHandling: UnknownLicenseHandling.Warn,
            unpinnedActionHandling: PolicyRiskHandling.Warn,
            requireSecurityPolicy: false,
            requireReleaseChecksums: false),
        TrustProfile.ProductionDependency => Create(
            "Production Dependency",
            profile,
            minimumScore: 75,
            maxVulnerabilitySeverity: Severity.High,
            unknownLicenseHandling: UnknownLicenseHandling.Warn,
            unpinnedActionHandling: PolicyRiskHandling.Warn,
            requireSecurityPolicy: true,
            requireReleaseChecksums: false),
        TrustProfile.EnterpriseDependency => Create(
            "Enterprise Dependency",
            profile,
            minimumScore: 82,
            maxVulnerabilitySeverity: Severity.Medium,
            unknownLicenseHandling: UnknownLicenseHandling.Block,
            unpinnedActionHandling: PolicyRiskHandling.Block,
            requireSecurityPolicy: true,
            requireReleaseChecksums: true,
            deniedLicenses: new HashSet<string>(["AGPL", "AGPL-3.0", "GPL-3.0"], StringComparer.OrdinalIgnoreCase)),
        TrustProfile.CiCdTool => Create(
            "CI/CD Tool",
            profile,
            minimumScore: 80,
            maxVulnerabilitySeverity: Severity.Medium,
            unknownLicenseHandling: UnknownLicenseHandling.Warn,
            unpinnedActionHandling: PolicyRiskHandling.Block,
            requireSecurityPolicy: true,
            requireReleaseChecksums: true),
        TrustProfile.SecuritySensitiveDependency => Create(
            "Security Sensitive Dependency",
            profile,
            minimumScore: 88,
            maxVulnerabilitySeverity: Severity.Low,
            unknownLicenseHandling: UnknownLicenseHandling.Block,
            unpinnedActionHandling: PolicyRiskHandling.Block,
            requireSecurityPolicy: true,
            requireReleaseChecksums: true),
        TrustProfile.ContainerDependency => Create(
            "Container Dependency",
            profile,
            minimumScore: 78,
            maxVulnerabilitySeverity: Severity.High,
            unknownLicenseHandling: UnknownLicenseHandling.Warn,
            unpinnedActionHandling: PolicyRiskHandling.Warn,
            requireSecurityPolicy: true,
            requireReleaseChecksums: true),
        _ => Create("Production Dependency", TrustProfile.ProductionDependency, 75, Severity.High, UnknownLicenseHandling.Warn, PolicyRiskHandling.Warn, true, false)
    };

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
                [AnalysisCategory.CiCd] = minimumScore
            },
            requireSecurityPolicy,
            unknownLicenseHandling,
            unpinnedActionHandling,
            requireReleaseChecksums,
            new HashSet<string>(["nuget.org", "registry.npmjs.org", "pypi.org"], StringComparer.OrdinalIgnoreCase));
    }
}

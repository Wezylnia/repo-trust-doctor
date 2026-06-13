using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;
using static RepoTrustDoctor.Analyzers.DependencyRisk.FindingFactory;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

public sealed class PackageMetadataAnalyzer(IReadOnlyCollection<IPackageMetadataClient> clients) : IRepositoryAnalyzer
{
    public string Id => "dependency-metadata";
    public string DisplayName => "Package Registry Metadata";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [DependencyInventoryArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.NetworkLookup;
    public TimeSpan Timeout => TimeSpan.FromSeconds(20);
    public IReadOnlyCollection<RuleMetadata> Rules => [];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<DependencyInventoryArtifact>(DependencyInventoryArtifact.ArtifactKey, out var inventory) || inventory is null)
        {
            return new AnalyzerResult(ModuleStatus.Skipped, []);
        }

        var metadata = new List<PackageRegistryMetadata>();
        var warnings = new List<string>();
        foreach (var package in DistinctPackagesForLookup(inventory.Packages
                     .Where(package =>
                         package.IsDirect &&
                         package.IsVersionPinned &&
                         !string.IsNullOrWhiteSpace(package.Version) &&
                         !DependencyRiskPathFilters.IsLikelyExampleOrTestManifest(package.ManifestPath)))
                     .Take(50))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var client = clients.FirstOrDefault(client => client.Ecosystem == package.Ecosystem);
            if (client is null)
            {
                continue;
            }

            try
            {
                if (await client.GetMetadataAsync(package, cancellationToken) is { } item)
                {
                    metadata.Add(WithDependencyContext(item, package));
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or FormatException)
            {
                warnings.Add($"Could not parse metadata for {package.Ecosystem}:{package.Name}: {ex.Message}");
            }
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.metadata.package.count"] = metadata.Count.ToString()
        };
        var artifact = new PackageMetadataArtifact(metadata, metrics);
        return AnalyzerResult.Completed([], [new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, artifact)], metrics, warnings);
    }

    private static PackageRegistryMetadata WithDependencyContext(PackageRegistryMetadata metadata, DependencyPackageInfo package)
    {
        var enriched = new Dictionary<string, string>(metadata.Metadata ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.scope"] = package.Scope.ToString(),
            ["dependency.manifestPath"] = package.ManifestPath,
            ["dependency.isDirect"] = package.IsDirect.ToString()
        };

        return metadata with { Metadata = enriched };
    }

    internal static IEnumerable<DependencyPackageInfo> DistinctPackagesForLookup(IEnumerable<DependencyPackageInfo> packages)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in packages)
        {
            var key = $"{package.Ecosystem}:{package.Name}:{package.Version}";
            if (seen.Add(key))
            {
                yield return package;
            }
        }
    }

}

internal static class DependencyRiskPathFilters
{
    public static bool IsLikelyExampleOrTestManifest(string manifestPath)
    {
        return RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(manifestPath);
    }
}

public sealed class PackageFreshnessAnalyzer : IRepositoryAnalyzer
{
    public string Id => "dependency-risk-freshness";
    public string DisplayName => "Package Freshness";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [PackageMetadataArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
    public TimeSpan Timeout => TimeSpan.FromSeconds(10);
    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DEP015", "Dependency appears outdated", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "A direct dependency has a newer major version available in package metadata.", "Review the dependency changelog and plan an update if compatible."),
        new("TRUST-DEP016", "Dependency package is deprecated or yanked", AnalysisCategory.Dependencies, Severity.High, Confidence.High, "Package registry metadata marks a dependency as deprecated or yanked.", "Replace deprecated packages or upgrade to a maintained version.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<PackageMetadataArtifact>(PackageMetadataArtifact.ArtifactKey, out var artifact) || artifact is null)
        {
            return Task.FromResult(new AnalyzerResult(ModuleStatus.Skipped, []));
        }

        var findings = new List<Finding>();
        foreach (var package in artifact.Packages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsDevelopmentDependency(package))
            {
                continue;
            }

            if (package.IsDeprecated || package.IsYanked)
            {
                findings.Add(CreateFinding(
                    "TRUST-DEP016",
                    "Dependency package is deprecated or yanked",
                    Severity.High,
                    Confidence.High,
                    $"Package `{package.Name}` is marked as deprecated or yanked by {package.SourceRegistry}.",
                    "package-metadata",
                    $"Package `{package.Name}` metadata indicates deprecated={package.IsDeprecated}, yanked={package.IsYanked}.",
                    "Replace deprecated packages or upgrade to a maintained version."));
            }

            if (!IsStablePackageWithPrereleaseLatest(package) &&
                MajorVersion(package.RequestedVersion) is { } requestedMajor &&
                MajorVersion(package.LatestVersion) is { } latestMajor &&
                latestMajor > requestedMajor)
            {
                findings.Add(CreateFinding(
                    "TRUST-DEP015",
                    "Dependency appears outdated",
                    Severity.Medium,
                    Confidence.Medium,
                    $"Package `{package.Name}` uses `{package.RequestedVersion}` while latest metadata reports `{package.LatestVersion}`.",
                    "package-metadata",
                    $"Package `{package.Name}` latest major version is newer.",
                    "Review the dependency changelog and plan an update if compatible."));
            }
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static int? MajorVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var first = version.Trim().TrimStart('v').Split('.', '-', '+')[0];
        return int.TryParse(first, out var major) ? major : null;
    }

    private static bool IsStablePackageWithPrereleaseLatest(PackageRegistryMetadata package) =>
        !IsPrereleaseVersion(package.RequestedVersion) &&
        IsPrereleaseVersion(package.LatestVersion);

    private static bool IsPrereleaseVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        version.Contains('-', StringComparison.Ordinal);

    private static bool IsDevelopmentDependency(PackageRegistryMetadata package) =>
        package.Metadata?.TryGetValue("dependency.scope", out var scope) == true &&
        scope.Equals(nameof(DependencyScope.Development), StringComparison.OrdinalIgnoreCase);
}

public sealed class DependencyVulnerabilityAnalyzer(IOsvAdvisoryClient osvClient) : IRepositoryAnalyzer
{
    public string Id => "dependency-risk-vulnerabilities";
    public string DisplayName => "Dependency Vulnerabilities";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [DependencyInventoryArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.NetworkLookup;
    public TimeSpan Timeout => TimeSpan.FromSeconds(30);
    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-VULN001", "Direct dependency has a known vulnerability", AnalysisCategory.Dependencies, Severity.High, Confidence.High, "OSV reports a known advisory for a direct dependency.", "Review the advisory and update the dependency to a fixed version when available."),
        new("TRUST-VULN002", "Transitive dependency has a known vulnerability", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "OSV reports a known advisory for a transitive dependency.", "Review whether the vulnerable transitive package is reachable and update the dependency chain where possible."),
        new("TRUST-VULN003", "Vulnerable dependency has a known fixed version", AnalysisCategory.Dependencies, Severity.Info, Confidence.High, "The advisory metadata includes at least one fixed version.", "Upgrade to a fixed version listed by the advisory when compatible.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<DependencyInventoryArtifact>(DependencyInventoryArtifact.ArtifactKey, out var inventory) || inventory is null)
        {
            return new AnalyzerResult(ModuleStatus.Skipped, []);
        }

        var findings = new List<Finding>();
        var cache = new Dictionary<string, IReadOnlyList<VulnerabilityAdvisory>>(StringComparer.OrdinalIgnoreCase);
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in PackageMetadataAnalyzer.DistinctPackagesForLookup(inventory.Packages
                     .Where(package =>
                         !string.IsNullOrWhiteSpace(package.Version) &&
                         !DependencyRiskPathFilters.IsLikelyExampleOrTestManifest(package.ManifestPath))
                     .OrderByDescending(package => package.IsDirect))
                     .Take(50))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = $"{package.Ecosystem}:{package.Name}:{package.Version}";
            if (!cache.TryGetValue(key, out var advisories))
            {
                advisories = await osvClient.QueryAsync(package, cancellationToken);
                cache[key] = advisories;
            }

            foreach (var advisory in advisories)
            {
                var reportKey = $"{package.Ecosystem}:{package.Name}:{package.Version}:{advisory.Id}";
                if (!reported.Add(reportKey))
                {
                    continue;
                }

                var ruleId = package.IsDirect ? "TRUST-VULN001" : "TRUST-VULN002";
                findings.Add(CreateFinding(
                    ruleId,
                    package.IsDirect ? "Direct dependency has a known vulnerability" : "Transitive dependency has a known vulnerability",
                    package.IsDirect ? advisory.Severity : Downgrade(advisory.Severity),
                    package.IsDirect ? Confidence.High : Confidence.Medium,
                    $"Package `{package.Name}` version `{package.Version}` matches advisory `{advisory.Id}`.",
                    "vulnerability-advisory",
                    $"Advisory `{advisory.Id}`: {advisory.Summary}",
                    "Review the advisory and update the dependency to a fixed version when available.",
                    tags: ["vulnerability", advisory.Id]));

                if (advisory.FixedVersions.Count > 0)
                {
                    findings.Add(CreateFinding(
                        "TRUST-VULN003",
                        "Vulnerable dependency has a known fixed version",
                        Severity.Info,
                        Confidence.High,
                        $"Advisory `{advisory.Id}` lists fixed version `{advisory.FixedVersions[0]}` for package `{package.Name}`.",
                        "vulnerability-advisory",
                        $"Fixed versions include `{string.Join(", ", advisory.FixedVersions.Take(3))}`.",
                        $"Upgrade `{package.Name}` to a fixed version listed by advisory `{advisory.Id}`.",
                        tags: ["vulnerability", advisory.Id]));
                }
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static Severity Downgrade(Severity severity) => severity switch
    {
        Severity.Critical => Severity.High,
        Severity.High => Severity.Medium,
        _ => severity
    };
}

public sealed class DependencyLicenseAnalyzer : IRepositoryAnalyzer
{
    public string Id => "dependency-risk-licenses";
    public string DisplayName => "Dependency Licenses";
    public AnalysisCategory Category => AnalysisCategory.Licenses;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [PackageMetadataArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
    public TimeSpan Timeout => TimeSpan.FromSeconds(10);
    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-LIC001", "Dependency license is unknown", AnalysisCategory.Licenses, Severity.Low, Confidence.Medium, "Package metadata contains an unrecognized license expression.", "Manually review the package license before production use."),
        new("TRUST-LIC002", "Dependency uses a policy-sensitive license", AnalysisCategory.Licenses, Severity.Medium, Confidence.Medium, "Package metadata indicates a copyleft license family such as GPL, LGPL, or AGPL.", "Review license obligations with the appropriate legal or compliance process."),
        new("TRUST-LIC003", "Package license metadata is missing", AnalysisCategory.Licenses, Severity.Low, Confidence.High, "Package metadata does not include a license expression.", "Prefer packages with clear license metadata or document the manual review result.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<PackageMetadataArtifact>(PackageMetadataArtifact.ArtifactKey, out var artifact) || artifact is null)
        {
            return Task.FromResult(new AnalyzerResult(ModuleStatus.Skipped, []));
        }

        var findings = new List<Finding>();
        foreach (var package in artifact.Packages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var license = PackageLicenseNormalizer.Normalize(package.LicenseExpression);
            if (string.IsNullOrWhiteSpace(package.LicenseExpression))
            {
                findings.Add(CreateFinding("TRUST-LIC003", "Package license metadata is missing", Severity.Low, Confidence.High, $"Package `{package.Name}` has no license metadata.", "license-metadata", $"Package `{package.Name}` license metadata is missing.", "Prefer packages with clear license metadata or document the manual review result."));
            }
            else if (!license.IsKnown)
            {
                findings.Add(CreateFinding("TRUST-LIC001", "Dependency license is unknown", Severity.Low, Confidence.Medium, $"Package `{package.Name}` has unrecognized license metadata.", "license-metadata", $"Package `{package.Name}` license expression is `{license.OriginalExpression}`.", "Manually review the package license before production use."));
            }
            else if (license.IsPolicySensitive)
            {
                findings.Add(CreateFinding("TRUST-LIC002", "Dependency uses a policy-sensitive license", Severity.Medium, Confidence.Medium, $"Package `{package.Name}` uses policy-sensitive license `{license.OriginalExpression}`.", "license-metadata", $"License family `{license.Family}` detected for `{package.Name}`.", "Review license obligations with the appropriate legal or compliance process."));
            }
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }
}

internal static class FindingFactory
{
    internal static Finding CreateFinding(
        string ruleId,
        string title,
        Severity severity,
        Confidence confidence,
        string message,
        string evidenceKind,
        string evidence,
        string recommendation,
        IReadOnlyList<string>? tags = null) =>
        new(
            ruleId,
            title,
            ruleId.StartsWith("TRUST-LIC", StringComparison.OrdinalIgnoreCase) ? AnalysisCategory.Licenses : AnalysisCategory.Dependencies,
            severity,
            confidence,
            message,
            [new Evidence(evidenceKind, evidence)],
            new Recommendation(recommendation),
            Tags: tags);
}


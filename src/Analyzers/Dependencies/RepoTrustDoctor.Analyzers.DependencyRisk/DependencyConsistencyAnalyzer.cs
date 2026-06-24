using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

public sealed class DependencyConsistencyAnalyzer : IRepositoryAnalyzer
{
    public string Id => "dependency.consistency";

    public string DisplayName => "Dependency Consistency";

    public AnalysisCategory Category => AnalysisCategory.Dependencies;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [DependencyInventoryArtifact.ArtifactKey];

    public IReadOnlyCollection<string> ProducesArtifacts => [DependencyConsistencyArtifact.ArtifactKey];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DEP052", "Direct production dependency uses multiple major versions",
            AnalysisCategory.Dependencies, Severity.Low, Confidence.High,
            "The same direct production dependency appears with different major versions across workspace projects.",
            "Standardize on a single major version of this dependency across the workspace."),
        new("TRUST-DEP053", "Package source differs across workspace projects",
            AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium,
            "The same package is resolved from different source kinds (registry, Git, path) across projects.",
            "Review whether differing package sources are intentional and avoid mixing registry and non-registry sources for the same package."),
        new("TRUST-DEP054", "Direct dependency is not represented by the detected lockfile",
            AnalysisCategory.Dependencies, Severity.Medium, Confidence.High,
            "A direct dependency declaration was not found in the applicable lockfile.",
            "Run the package manager install or restore command to update the lockfile and commit the result.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<DependencyInventoryArtifact>(DependencyInventoryArtifact.ArtifactKey, out var inventory) || inventory is null)
        {
            return Task.FromResult(new AnalyzerResult(
                ModuleStatus.Completed,
                [],
                null,
                null,
                ["Dependency inventory artifact was not available; consistency checks were skipped."]));
        }

        var directPackages = inventory.Packages
            .Where(p => p.IsDirect)
            .ToArray();

        var productionPackages = directPackages
            .Where(p => p.Scope is DependencyScope.Production or DependencyScope.Unknown)
            .ToArray();

        // Group by ecosystem + normalized name
        var versionGroups = BuildVersionGroups(productionPackages);
        var sourceGroups = BuildSourceGroups(productionPackages);

        var findings = new List<Finding>();

        // TRUST-DEP052: major-version drift
        foreach (var group in versionGroups)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var versionedPackages = group.Packages
                .Where(p => !string.IsNullOrWhiteSpace(p.Version))
                .Select(p => (Package: p, Major: ParseExactMajorVersion(p.Version!)))
                .Where(x => x.Major.HasValue)
                .ToArray();

            if (versionedPackages.Length < 2)
            {
                continue;
            }

            var distinctMajors = versionedPackages
                .Select(x => x.Major!.Value)
                .Distinct()
                .ToArray();

            if (distinctMajors.Length < 2)
            {
                continue;
            }

            var distinctManifests = versionedPackages
                .Select(x => x.Package.ManifestPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            var severity = distinctMajors.Length >= 3 || distinctManifests >= 3
                ? Severity.Medium
                : Severity.Low;

            var allExact = versionedPackages.All(x => true); // all have parsed majors, all are exact

            var evidenceItems = versionedPackages
                .Take(10)
                .Select(x => new Evidence(
                    "dependency-version",
                    $"Package `{x.Package.Name}` version `{x.Package.Version}` (major {x.Major}) in `{x.Package.ManifestPath}`.",
                    x.Package.ManifestPath))
                .ToArray();

            findings.Add(new Finding(
                "TRUST-DEP052",
                "Direct production dependency uses multiple major versions",
                AnalysisCategory.Dependencies,
                severity,
                allExact ? Confidence.High : Confidence.Medium,
                $"Package `{group.NormalizedName}` appears with {distinctMajors.Length} different major versions across the workspace.",
                evidenceItems,
                new Recommendation("Standardize on a single major version of this dependency across the workspace."),
                IdentityKey: $"dep052|{group.Ecosystem.ToString().ToLowerInvariant()}|{group.NormalizedName.ToLowerInvariant()}"));
        }

        // TRUST-DEP053 and TRUST-DEP054 added in subsequent commits

        var artifact = new DependencyConsistencyArtifact(
            VersionGroups: versionGroups,
            SourceGroups: sourceGroups,
            Metrics: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["dependency.consistency.package.count"] = inventory.Packages.Count.ToString(),
                ["dependency.consistency.direct.count"] = directPackages.Length.ToString(),
                ["dependency.consistency.group.count"] = (versionGroups.Count + sourceGroups.Count).ToString()
            });

        return Task.FromResult(AnalyzerResult.Completed(
            findings,
            artifacts: [new AnalyzerArtifact(DependencyConsistencyArtifact.ArtifactKey, artifact)],
            metrics: artifact.Metrics));
    }

    internal static List<DependencyVersionGroup> BuildVersionGroups(IReadOnlyList<DependencyPackageInfo> packages)
    {
        var groups = new Dictionary<string, List<DependencyPackageInfo>>(StringComparer.OrdinalIgnoreCase);

        foreach (var package in packages)
        {
            var key = $"{package.Ecosystem}|{NormalizePackageName(package.Ecosystem, package.Name)}";
            if (!groups.TryGetValue(key, out var list))
            {
                list = [];
                groups[key] = list;
            }
            list.Add(package);
        }

        return groups
            .Select(kvp => new DependencyVersionGroup(
                kvp.Value[0].Ecosystem,
                NormalizePackageName(kvp.Value[0].Ecosystem, kvp.Value[0].Name),
                kvp.Value))
            .OrderBy(g => g.Ecosystem)
            .ThenBy(g => g.NormalizedName)
            .ToList();
    }

    internal static List<DependencySourceGroup> BuildSourceGroups(IReadOnlyList<DependencyPackageInfo> packages)
    {
        var groups = new Dictionary<string, List<DependencyPackageInfo>>(StringComparer.OrdinalIgnoreCase);

        foreach (var package in packages)
        {
            var key = $"{package.Ecosystem}|{NormalizePackageName(package.Ecosystem, package.Name)}";
            if (!groups.TryGetValue(key, out var list))
            {
                list = [];
                groups[key] = list;
            }
            list.Add(package);
        }

        return groups
            .Select(kvp => new DependencySourceGroup(
                kvp.Value[0].Ecosystem,
                NormalizePackageName(kvp.Value[0].Ecosystem, kvp.Value[0].Name),
                kvp.Value))
            .OrderBy(g => g.Ecosystem)
            .ThenBy(g => g.NormalizedName)
            .ToList();
    }

    internal static string NormalizePackageName(DependencyEcosystem ecosystem, string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        return ecosystem switch
        {
            DependencyEcosystem.Npm => NormalizeNpmName(name),
            DependencyEcosystem.Python => NormalizePythonName(name),
            _ => name.Trim()
        };
    }

    private static string NormalizeNpmName(string name)
    {
        // npm scoped packages: @scope/name stays as-is but lowercased
        return name.Trim().ToLowerInvariant();
    }

    private static string NormalizePythonName(string name)
    {
        // PyPI: normalize separators: -, _, . are all treated equivalently for identity
        return name.Trim().ToLowerInvariant().Replace('-', '_').Replace('.', '_');
    }

    /// <summary>
    /// Parses the major version from an exact semantic version string like "1.2.3".
    /// Returns null for ranges, tags, Git refs, prerelease-only, or malformed versions.
    /// </summary>
    internal static int? ParseExactMajorVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var trimmed = version.Trim();

        // Skip ranges, tags, and non-exact specifiers
        if (trimmed.StartsWith('^') || trimmed.StartsWith('~') || trimmed.StartsWith('>') ||
            trimmed.StartsWith('<') || trimmed.StartsWith('=') || trimmed.StartsWith('[') ||
            trimmed.StartsWith('*') || trimmed.StartsWith('x') || trimmed.StartsWith('X'))
        {
            return null;
        }

        // Skip common non-version strings
        if (trimmed.Equals("latest", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("main", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("master", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Contains('/')) // Git refs
        {
            return null;
        }

        // Allow optional 'v' prefix
        var versionPart = trimmed.StartsWith("v", StringComparison.OrdinalIgnoreCase)
            ? trimmed[1..]
            : trimmed;

        // Split on . - +
        var dotIndex = versionPart.IndexOf('.');
        var dashIndex = versionPart.IndexOf('-');
        var plusIndex = versionPart.IndexOf('+');
        var firstDot = dotIndex >= 0 ? dotIndex : int.MaxValue;
        if (dashIndex >= 0 && dashIndex < firstDot) firstDot = dashIndex;
        if (plusIndex >= 0 && plusIndex < firstDot) firstDot = plusIndex;
        if (firstDot == int.MaxValue) firstDot = -1;
        var majorStr = firstDot > 0 ? versionPart[..firstDot] : versionPart;

        if (int.TryParse(majorStr, out var major))
        {
            return major;
        }

        return null;
    }
}

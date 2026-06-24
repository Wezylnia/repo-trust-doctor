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

        var artifact = new DependencyConsistencyArtifact(
            VersionGroups: versionGroups,
            SourceGroups: sourceGroups,
            Metrics: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["dependency.consistency.package.count"] = inventory.Packages.Count.ToString(),
                ["dependency.consistency.direct.count"] = directPackages.Length.ToString(),
                ["dependency.consistency.group.count"] = (versionGroups.Count + sourceGroups.Count).ToString()
            });

        // No findings emitted in this shell commit; findings come in subsequent commits.
        return Task.FromResult(AnalyzerResult.Completed(
            [],
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
}

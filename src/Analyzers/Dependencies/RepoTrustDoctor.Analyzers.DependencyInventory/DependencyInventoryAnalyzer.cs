using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

public sealed class DependencyInventoryAnalyzer : IRepositoryAnalyzer
{
    private static readonly IReadOnlyList<IDependencyInventoryCollector> Collectors =
    [
        new NpmDependencyCollector(),
        new NuGetDependencyCollector(),
        new PythonDependencyCollector(),
        new JavaDependencyCollector(),
        new GoDependencyCollector()
    ];

    public string Id => "dependency-inventory";

    public string DisplayName => "Dependency Inventory";

    public AnalysisCategory Category => AnalysisCategory.Dependencies;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DEP001", "npm manifest exists without lockfile", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json file exists but no lockfile was found.", "Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository."),
        new("TRUST-DEP002", "NuGet project does not use lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A NuGet project exists but no packages.lock.json was found.", "Enable NuGet lock files and commit packages.lock.json to the repository."),
        new("TRUST-DEP003", "Python dependency manifest does not have a recognized lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A Python dependency manifest exists but no recognized lockfile was found.", "Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository."),
        new("TRUST-DEP004", "NuGet dependency uses a floating or unpinned version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A direct NuGet dependency is missing an exact pinned version or uses a floating/ranged version.", "Pin direct NuGet dependency versions or resolve them through Central Package Management."),
        new("TRUST-DEP005", "NuGet dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A direct NuGet dependency uses a prerelease version.", "Review whether the prerelease dependency is intentional before production use."),
        new("TRUST-DEP006", "npm dependency uses a range or unpinned version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json dependency uses a range, tag, workspace reference, or otherwise non-exact version.", "Use exact dependency versions together with a committed lockfile for reproducible installs."),
        new("TRUST-DEP007", "npm dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A package.json dependency uses a prerelease version.", "Review prerelease dependencies and prefer stable versions where possible."),
        new("TRUST-DEP008", "npm install-time script requires manual review", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "package.json defines an install-time script such as preinstall, install, or postinstall.", "Manually review install-time scripts because they run during package installation."),
        new("TRUST-DEP009", "Python requirement is unpinned", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A Python dependency is not pinned to an exact version.", "Pin Python requirements or use a lockfile-based package manager."),
        new("TRUST-DEP010", "Python dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A Python dependency uses a prerelease version.", "Review whether the prerelease dependency is intentional before production use."),
        new("TRUST-DEP011", "npm dependency uses a direct remote source", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json dependency points directly at a Git or URL source instead of a registry version.", "Review direct remote dependency sources and prefer registry packages with pinned versions when possible."),
        new("TRUST-DEP012", "npm dependency uses a local file source", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A package.json dependency points at a local file, link, workspace, or portal source.", "Review local dependency sources because they depend on repository layout and may bypass registry provenance."),
        new("TRUST-DEP013", "NuGet package source uses insecure transport", AnalysisCategory.Dependencies, Severity.High, Confidence.High, "NuGet.config defines an HTTP package source.", "Use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport."),
        new("TRUST-DEP014", "NuGet package source uses a local path", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "NuGet.config defines a local package source.", "Review local package sources because they can change package origin assumptions and may hide dependency confusion risk."),
        new("TRUST-DEP017", "Java dependency manifest does not have a recognized lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A Maven or Gradle dependency manifest exists without a recognized dependency lockfile.", "Commit Gradle dependency locking output or equivalent dependency lock evidence for repeatable Java builds."),
        new("TRUST-DEP018", "Java dependency uses a dynamic or unpinned version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A Maven or Gradle dependency uses a missing, dynamic, property-based, or ranged version.", "Pin Java dependency versions or resolve them through a reviewed platform/BOM."),
        new("TRUST-DEP019", "Java dependency uses a snapshot or prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A Maven or Gradle dependency uses a SNAPSHOT or prerelease version.", "Review whether the Java prerelease dependency is intentional before production use."),
        new("TRUST-DEP020", "Gradle project does not include wrapper scripts", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A Gradle build exists but the repository does not include Gradle wrapper scripts.", "Commit gradlew, gradlew.bat, and the wrapper properties file so reviewers can see the expected Gradle distribution."),
        new("TRUST-DEP021", "Spring Boot Actuator exposes broad endpoint access", AnalysisCategory.Dependencies, Severity.High, Confidence.Medium, "Spring Boot Actuator appears configured to expose all web endpoints.", "Restrict management.endpoints.web.exposure.include to the minimum required endpoints and protect management interfaces."),
        new("TRUST-DEP022", "Go module does not have a go.sum file", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A go.mod file exists but no go.sum was found.", "Run 'go mod tidy' and commit go.sum to the repository for reproducible builds."),
        new("TRUST-DEP023", "Go module uses replace directive", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "The go.mod file contains a replace directive.", "Review replace directives because they override resolved module versions."),
        new("TRUST-DEP024", "Go dependency uses a non-exact version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A Go module dependency does not use an exact pinned version.", "Use exact versions with a committed go.sum for reproducible Go builds."),
        new("TRUST-DEP025", "Go dependency uses a pseudo-version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A Go module dependency references a pseudo-version.", "Prefer tagged releases over pseudo-versions and review pseudo-version origins.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var state = new DependencyInventoryState();
        foreach (var collector in Collectors)
        {
            collector.Collect(context, state, cancellationToken);
        }

        var metrics = DependencyInventoryMetrics.Build(state);
        var artifact = new DependencyInventoryArtifact(
            state.Manifests,
            state.Lockfiles,
            state.Packages,
            state.PackageSources,
            metrics);

        return Task.FromResult(AnalyzerResult.Completed(
            state.Findings,
            [new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, artifact)],
            metrics,
            state.Warnings));
    }
}

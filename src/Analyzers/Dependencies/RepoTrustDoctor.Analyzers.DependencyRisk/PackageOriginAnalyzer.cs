using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using static RepoTrustDoctor.Analyzers.DependencyRisk.FindingFactory;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

public sealed class PackageOriginAnalyzer : IRepositoryAnalyzer
{
    public string Id => "dependency-risk-origin";
    public string DisplayName => "Package Origin";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [DependencyInventoryArtifact.ArtifactKey, PackageMetadataArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
    public TimeSpan Timeout => TimeSpan.FromSeconds(10);
    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-ORIGIN001", "Package repository URL does not match analyzed repository", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "Package registry metadata points at a different repository URL than the scanned target.", "Verify that package metadata points to the expected source repository."),
        new("TRUST-ORIGIN002", "Package has official-looking name from unverified origin", AnalysisCategory.Dependencies, Severity.Low, Confidence.Low, "A package name resembles an official namespace but metadata is incomplete.", "Manually verify the package publisher and repository before relying on it."),
        new("TRUST-ORIGIN003", "Package origin metadata is incomplete", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "Package metadata does not include a repository URL.", "Prefer dependencies with traceable repository metadata."),
        new("TRUST-ORIGIN004", "Package source mapping is missing for mixed NuGet sources", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "NuGet configuration mixes public and non-public package sources without visible source mapping.", "Add NuGet package source mapping to reduce dependency confusion risk."),
        new("TRUST-ORIGIN005", "npm scope registry configuration appears risky", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "Scoped npm dependencies appear without matching scoped registry configuration.", "Add explicit scope registry mapping in .npmrc for private scopes."),
        new("TRUST-ORIGIN006", "Internal-looking package is resolved from a public registry", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "A dependency name looks internal but appears to use a public registry source.", "Verify whether the package should come from a private registry.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        context.TryGetArtifact<DependencyInventoryArtifact>(DependencyInventoryArtifact.ArtifactKey, out var inventory);
        context.TryGetArtifact<PackageMetadataArtifact>(PackageMetadataArtifact.ArtifactKey, out var metadata);
        var packageScopes = BuildScopeLookup(inventory);

        if (metadata is not null)
        {
            foreach (var package in metadata.Packages)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var shouldReportOriginMetadata = IsProductionOrUnknownScope(package, packageScopes);
                if (string.IsNullOrWhiteSpace(package.RepositoryUrl) && shouldReportOriginMetadata)
                {
                    findings.Add(CreateFinding("TRUST-ORIGIN003", "Package origin metadata is incomplete", Severity.Low, Confidence.Medium, $"Package `{package.Name}` metadata does not include a repository URL.", "package-origin", $"Package `{package.Name}` has no repository URL in {package.SourceRegistry}.", "Prefer dependencies with traceable repository metadata."));
                }
                else if (!string.IsNullOrWhiteSpace(package.RepositoryUrl) &&
                         ShouldCompareRepositoryToTarget(context.Target, package) &&
                         IsRepositoryMismatch(context.Target, package.RepositoryUrl))
                {
                    findings.Add(CreateFinding("TRUST-ORIGIN001", "Package repository URL does not match analyzed repository", Severity.Medium, Confidence.Medium, $"Package `{package.Name}` repository metadata points to a different repository.", "package-origin", $"Repository metadata is `{package.RepositoryUrl}`.", "Verify that package metadata points to the expected source repository."));
                }

                if (LooksOfficial(package.Name) && string.IsNullOrWhiteSpace(package.RepositoryUrl) && shouldReportOriginMetadata)
                {
                    findings.Add(CreateFinding("TRUST-ORIGIN002", "Package has official-looking name from unverified origin", Severity.Low, Confidence.Low, $"Package `{package.Name}` has an official-looking name but incomplete origin metadata.", "package-origin", $"Package `{package.Name}` needs publisher/origin review.", "Manually verify the package publisher and repository before relying on it."));
                }
            }
        }

        if (inventory is not null)
        {
            AddDependencyConfusionFindings(context, inventory, findings);
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static Dictionary<string, DependencyScope> BuildScopeLookup(DependencyInventoryArtifact? inventory)
    {
        var lookup = new Dictionary<string, DependencyScope>(StringComparer.OrdinalIgnoreCase);
        if (inventory is null)
        {
            return lookup;
        }

        foreach (var package in inventory.Packages.Where(package => package.IsDirect))
        {
            lookup[PackageKey(package.Ecosystem, package.Name, package.Version)] = package.Scope;
        }

        return lookup;
    }

    private static bool IsProductionOrUnknownScope(PackageRegistryMetadata package, IReadOnlyDictionary<string, DependencyScope> scopes)
    {
        var scope = ReadMetadataScope(package) ??
                    (scopes.TryGetValue(PackageKey(package.Ecosystem, package.Name, package.RequestedVersion), out var inventoryScope)
                        ? inventoryScope
                        : DependencyScope.Unknown);

        return scope is DependencyScope.Production or DependencyScope.Optional or DependencyScope.Peer or DependencyScope.Unknown;
    }

    private static DependencyScope? ReadMetadataScope(PackageRegistryMetadata package)
    {
        if (package.Metadata?.TryGetValue("scope", out var value) == true &&
            Enum.TryParse<DependencyScope>(value, ignoreCase: true, out var scope))
        {
            return scope;
        }

        return null;
    }

    private static void AddDependencyConfusionFindings(AnalysisContext context, DependencyInventoryArtifact inventory, List<Finding> findings)
    {
        var hasNuGetPublic = inventory.PackageSources.Any(source => source.Ecosystem == DependencyEcosystem.NuGet && source.Source.Contains("nuget.org", StringComparison.OrdinalIgnoreCase));
        var hasNuGetNonPublic = inventory.PackageSources.Any(source => source.Ecosystem == DependencyEcosystem.NuGet && !source.Source.Contains("nuget.org", StringComparison.OrdinalIgnoreCase));
        if (hasNuGetPublic && hasNuGetNonPublic && !NuGetSourceMappingExists(context.RepositoryPath))
        {
            findings.Add(CreateFinding("TRUST-ORIGIN004", "Package source mapping is missing for mixed NuGet sources", Severity.Medium, Confidence.Medium, "NuGet config mixes public and non-public package sources without visible packageSourceMapping.", "nuget-source", "Mixed NuGet sources were detected without package source mapping.", "Add NuGet package source mapping to reduce dependency confusion risk."));
        }

        foreach (var package in inventory.Packages.Where(package => package.Ecosystem == DependencyEcosystem.Npm))
        {
            if (package.Name.StartsWith("@", StringComparison.Ordinal) &&
                LooksInternal(package.Name) &&
                !NpmScopeRegistryExists(context.RepositoryPath, package.Name))
            {
                findings.Add(CreateFinding("TRUST-ORIGIN005", "npm scope registry configuration appears risky", Severity.Medium, Confidence.Medium, $"Scoped package `{package.Name}` appears internal but no scope registry mapping was found.", "npm-registry", $"Package `{package.Name}` has no matching .npmrc scope registry mapping.", "Add explicit scope registry mapping in .npmrc for private scopes."));
            }

            var sourceKind = string.Empty;
            var hasSourceKind = package.Metadata?.TryGetValue("sourceKind", out sourceKind) == true;
            var isRegistryResolved = !hasSourceKind ||
                                     string.Equals(sourceKind, "registry", StringComparison.OrdinalIgnoreCase);
            if (LooksInternal(package.Name) && isRegistryResolved)
            {
                findings.Add(CreateFinding("TRUST-ORIGIN006", "Internal-looking package is resolved from a public registry", Severity.Medium, Confidence.Medium, $"Package `{package.Name}` looks internal but appears to use registry resolution.", "package-origin", $"Package `{package.Name}` should be verified against expected registry sources.", "Verify whether the package should come from a private registry."));
            }
        }
    }

    private static bool NpmScopeRegistryExists(string repositoryPath, string packageName)
    {
        var scope = GetNpmScope(packageName);
        if (scope is null)
        {
            return false;
        }

        var prefix = scope + ":registry";
        foreach (var npmrc in RepositoryFileSystem.EnumerateFiles(repositoryPath, ".npmrc"))
        {
            if (!TryReadText(npmrc, out var content))
            {
                continue;
            }

            var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 ||
                    trimmed.StartsWith('#') ||
                    trimmed.StartsWith(';') ||
                    !trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var remainder = trimmed[prefix.Length..].TrimStart();
                if (remainder.StartsWith('='))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string? GetNpmScope(string packageName)
    {
        if (!packageName.StartsWith('@'))
        {
            return null;
        }

        var slash = packageName.IndexOf('/');
        return slash > 1 ? packageName[..slash] : null;
    }

    private static bool NuGetSourceMappingExists(string repositoryPath)
    {
        foreach (var config in RepositoryFileSystem.EnumerateFiles(repositoryPath, "NuGet.config"))
        {
            if (TryReadText(config, out var content) &&
                content.Contains("packageSourceMapping", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ShouldCompareRepositoryToTarget(string target, PackageRegistryMetadata package)
    {
        if (string.IsNullOrWhiteSpace(package.RepositoryUrl) ||
            !Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
        {
            return false;
        }

        var targetName = NormalizePackageName(Path.GetFileName(targetUri.AbsolutePath.TrimEnd('/')));
        var packageName = NormalizePackageName(package.Name);
        return targetName.Length > 0 &&
               (string.Equals(targetName, packageName, StringComparison.OrdinalIgnoreCase) ||
                packageName.EndsWith($"/{targetName}", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRepositoryMismatch(string target, string repositoryUrl)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri) ||
            !Uri.TryCreate(repositoryUrl.Replace("git+", string.Empty, StringComparison.OrdinalIgnoreCase), UriKind.Absolute, out var repoUri))
        {
            return false;
        }

        return !targetUri.Host.Equals(repoUri.Host, StringComparison.OrdinalIgnoreCase) ||
               !NormalizeRepoPath(targetUri.AbsolutePath).Equals(NormalizeRepoPath(repoUri.AbsolutePath), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRepoPath(string path) => path.Trim('/').Replace(".git", string.Empty, StringComparison.OrdinalIgnoreCase);

    private static string NormalizePackageName(string name)
    {
        var normalized = name.Trim().TrimStart('@').Replace(".git", string.Empty, StringComparison.OrdinalIgnoreCase);
        var slash = normalized.LastIndexOf('/');
        return slash >= 0 ? normalized[(slash + 1)..] : normalized;
    }

    private static string PackageKey(DependencyEcosystem ecosystem, string name, string? version) =>
        $"{ecosystem}:{name}:{version ?? string.Empty}";

    private static bool LooksOfficial(string name) =>
        name.Contains("microsoft", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("google", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("aws", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("azure", StringComparison.OrdinalIgnoreCase);

    private static bool LooksInternal(string name) =>
        name.Contains("internal", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("private", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("@company/", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("@internal/", StringComparison.OrdinalIgnoreCase);

    private static bool TryReadText(string path, out string content)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(path))
        {
            return false;
        }

        try
        {
            content = File.ReadAllText(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
        {
            return false;
        }
    }
}


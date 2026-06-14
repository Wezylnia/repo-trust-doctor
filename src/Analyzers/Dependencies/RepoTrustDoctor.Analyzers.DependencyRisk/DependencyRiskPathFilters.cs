using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

internal static class DependencyRiskPathFilters
{
    public static bool IsRegistryLookupEligible(DependencyPackageInfo package)
    {
        return package.Metadata?.TryGetValue("sourceKind", out var sourceKind) != true ||
               string.Equals(sourceKind, "registry", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsLikelyExampleOrTestManifest(string manifestPath)
    {
        return RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(manifestPath);
    }
}

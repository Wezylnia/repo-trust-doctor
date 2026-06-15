using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyRiskSourceKindTests
{
    [Fact]
    public async Task PackageMetadataAnalyzer_QueriesRegistryPackagesOnly()
    {
        var client = new TrackingMetadataClient();
        var analyzer = new PackageMetadataAnalyzer([client]);

        var result = await analyzer.AnalyzeAsync(CreateContext(), CancellationToken.None);
        var artifact = Assert.IsType<PackageMetadataArtifact>(
            Assert.Single(result.Artifacts!, item => item.Key == PackageMetadataArtifact.ArtifactKey).Value);

        Assert.Equal("real-package", Assert.Single(artifact.Packages).Name);
        Assert.Equal(1, client.QueryCount);
        Assert.Equal("1", result.Metrics!["dependency.metadata.candidate.count"]);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_DoesNotQueryWorkspaceOrLocalPackages()
    {
        var client = new TrackingOsvClient();
        var analyzer = new DependencyVulnerabilityAnalyzer(client);

        var result = await analyzer.AnalyzeAsync(CreateContext(), CancellationToken.None);

        Assert.Equal(1, client.QueryCount);
        Assert.Equal("1", result.Metrics!["dependency.vulnerability.candidate.count"]);
        Assert.Equal("1", result.Metrics["dependency.vulnerability.supported.count"]);
    }

    private static AnalysisContext CreateContext()
    {
        var packages = new[]
        {
            CreatePackage(
                "real-package",
                new Dictionary<string, string> { ["sourceKind"] = "registry", ["declaredName"] = "compat-package" }),
            CreatePackage(
                "workspace-package",
                new Dictionary<string, string> { ["sourceKind"] = "workspace" }),
            CreatePackage(
                "local-package",
                new Dictionary<string, string> { ["sourceKind"] = "local" })
        };
        var context = new AnalysisContext(".", ".", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(
            DependencyInventoryArtifact.ArtifactKey,
            new DependencyInventoryArtifact([], [], packages, [], new Dictionary<string, string>())));
        return context;
    }

    private static DependencyPackageInfo CreatePackage(
        string name,
        IReadOnlyDictionary<string, string> metadata) =>
        new(
            DependencyEcosystem.Npm,
            name,
            "2.4.1",
            DependencyScope.Production,
            "package.json",
            null,
            true,
            true,
            false,
            metadata);

    private sealed class TrackingMetadataClient : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem => DependencyEcosystem.Npm;

        public int QueryCount { get; private set; }

        public Task<PackageMetadataLookupResult> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            QueryCount++;
            return Task.FromResult(PackageMetadataLookupResult.Found(
                new PackageRegistryMetadata(
                    package.Ecosystem,
                    package.Name,
                    package.Version,
                    package.Version,
                    null,
                    false,
                    false,
                    null,
                    null,
                    "MIT",
                    null,
                    "registry.npmjs.org")));
        }
    }

    private sealed class TrackingOsvClient : IOsvAdvisoryClient
    {
        public int QueryCount { get; private set; }

        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            QueryCount++;
            return Task.FromResult<IReadOnlyList<VulnerabilityAdvisory>>([]);
        }
    }
}

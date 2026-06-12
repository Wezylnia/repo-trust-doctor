using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyRiskAnalyzerTests
{
    [Fact]
    public async Task PackageMetadataAnalyzer_EmitsMetadataArtifact_FromFakeClient()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "safe-lib", "1.0.0")
        ]);
        var analyzer = new PackageMetadataAnalyzer([new FakeMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        var package = Assert.Single(metadata.Packages);
        Assert.Equal(nameof(DependencyScope.Production), package.Metadata?["dependency.scope"]);
        Assert.Equal("1", metadata.Metrics["dependency.metadata.package.count"]);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_SkipsExampleAndTestManifestPackages()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "production-lib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "fixture-lib", "1.0.0", manifestPath: "packages/tool/__tests__/package.json"),
            CreatePackage(DependencyEcosystem.Npm, "playground-lib", "1.0.0", manifestPath: "playground/demo/package.json")
        ]);
        var analyzer = new PackageMetadataAnalyzer([new FakeMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        var package = Assert.Single(metadata.Packages);
        Assert.Equal("production-lib", package.Name);
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_ReportsOutdatedAndDeprecatedPackages()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "old-lib", "1.0.0", "2.0.0", null, false, false, null, null, "MIT", null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "deprecated-lib", "1.0.0", "1.0.0", null, true, false, null, null, "MIT", null, "registry.npmjs.org")
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP015");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP016");
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_IgnoresPrereleaseLatestForStablePackage()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.NuGet, "stable-lib", "3.2.2", "4.0.0-pre.1", null, false, false, null, null, "MIT", null, "nuget.org")
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP015");
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_SkipsDevelopmentDependencies()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(
                DependencyEcosystem.NuGet,
                "xunit",
                "2.9.0",
                "3.0.0",
                null,
                true,
                false,
                null,
                null,
                "MIT",
                null,
                "nuget.org",
                new Dictionary<string, string> { ["dependency.scope"] = nameof(DependencyScope.Development) })
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_ReportsDirectVulnerabilityAndFixedVersion()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "vulnerable-lib", "1.0.0")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-test", [], "test advisory", Severity.High, ["2.0.0"], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-VULN001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-VULN003");
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_SkipsExampleAndTestManifestPackages()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "fixture-lib", "1.0.0", manifestPath: "playground/demo/package.json")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-test", [], "test advisory", Severity.High, ["2.0.0"], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task DependencyLicenseAnalyzer_ReportsMissingUnknownAndCopyleftLicenses()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "missing", "1.0.0", "1.0.0", null, false, false, null, null, null, null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "unknown", "1.0.0", "1.0.0", null, false, false, null, null, "custom", null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "copyleft", "1.0.0", "1.0.0", null, false, false, null, null, "GPL-3.0-only", null, "registry.npmjs.org")
        ]);

        var result = await new DependencyLicenseAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC003");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_ReportsMissingRepositoryAndMixedNuGetSources()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "NuGet.config"), """
        <configuration>
          <packageSources>
            <add key="nuget" value="https://api.nuget.org/v3/index.json" />
            <add key="internal" value="https://packages.example.test/index.json" />
          </packageSources>
        </configuration>
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, new DependencyInventoryArtifact(
            [],
            [],
            [],
            [
                new DependencyPackageSourceInfo(DependencyEcosystem.NuGet, "nuget", "https://api.nuget.org/v3/index.json", "NuGet.config"),
                new DependencyPackageSourceInfo(DependencyEcosystem.NuGet, "internal", "https://packages.example.test/index.json", "NuGet.config")
            ],
            new Dictionary<string, string>())));
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.Npm, "microsoft-helper", "1.0.0", "1.0.0", null, false, false, null, null, "MIT", null, "registry.npmjs.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN003");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN004");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN002");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_SkipsMissingRepositoryForDevelopmentPackages()
    {
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.NuGet, "xunit.v3", "3.2.2", DependencyScope.Development)
        ]);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.NuGet, "xunit.v3", "3.2.2", "3.2.2", null, false, false, null, null, "MIT", null, "nuget.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN003");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_DoesNotCompareThirdPartyDependencyRepositoryToTarget()
    {
        var context = new AnalysisContext(".", "https://github.com/example/application", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.Npm, "react", "19.0.0", "19.0.0", null, false, false, "https://github.com/facebook/react", null, "MIT", null, "registry.npmjs.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN001");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_RequiresMatchingNpmScopeRegistry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), """
        @other:registry=https://npm.example.test/
        """);
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.Npm, "@internal/widget", "1.0.0")
        ], fixture.Path);

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN005");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_AcceptsMatchingNpmScopeRegistry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), """
        @internal:registry = https://npm.example.test/
        """);
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.Npm, "@internal/widget", "1.0.0")
        ], fixture.Path);

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN005");
    }

    private static AnalysisContext CreateContextWithInventory(IReadOnlyList<DependencyPackageInfo> packages, string repositoryPath = ".")
    {
        var context = new AnalysisContext(repositoryPath, repositoryPath, AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, new DependencyInventoryArtifact([], [], packages, [], new Dictionary<string, string>())));
        return context;
    }

    private static AnalysisContext CreateContextWithMetadata(IReadOnlyList<PackageRegistryMetadata> packages)
    {
        var context = new AnalysisContext(".", ".", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(packages, new Dictionary<string, string>())));
        return context;
    }

    private static DependencyPackageInfo CreatePackage(
        DependencyEcosystem ecosystem,
        string name,
        string version,
        DependencyScope scope = DependencyScope.Production,
        string manifestPath = "manifest") =>
        new(ecosystem, name, version, scope, manifestPath, null, true, true, false);

    private sealed class FakeMetadataClient(DependencyEcosystem ecosystem) : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem { get; } = ecosystem;

        public Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken) =>
            Task.FromResult<PackageRegistryMetadata?>(new PackageRegistryMetadata(package.Ecosystem, package.Name, package.Version, package.Version, null, false, false, "https://github.com/example/repo", null, "MIT", null, "fake"));
    }

    private sealed class FakeOsvClient(IReadOnlyList<VulnerabilityAdvisory> advisories) : IOsvAdvisoryClient
    {
        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(DependencyPackageInfo package, CancellationToken cancellationToken) =>
            Task.FromResult(advisories);
    }
}

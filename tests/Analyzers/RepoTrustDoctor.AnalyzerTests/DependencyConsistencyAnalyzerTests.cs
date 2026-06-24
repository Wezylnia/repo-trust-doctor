using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyConsistencyAnalyzerTests
{
    [Fact]
    public async Task Analyzer_ProducesConsistencyArtifact_FromInventory()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "safe-lib", "1.0.0")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == DependencyConsistencyArtifact.ArtifactKey);
        var consistency = Assert.IsType<DependencyConsistencyArtifact>(artifact.Value);
        Assert.Equal("1", consistency.Metrics["dependency.consistency.direct.count"]);
    }

    [Fact]
    public async Task Analyzer_ReturnsWarning_WhenInventoryMissing()
    {
        var context = new AnalysisContext("test", "/repo", AnalysisDepth.Standard);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        Assert.Empty(result.Findings);
        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, w => w.Contains("inventory", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NormalizePackageName_Npm_ScopedPackages()
    {
        Assert.Equal("@scope/mypackage", DependencyConsistencyAnalyzer.NormalizePackageName(DependencyEcosystem.Npm, "@Scope/MyPackage"));
        Assert.Equal("@scope/mypackage", DependencyConsistencyAnalyzer.NormalizePackageName(DependencyEcosystem.Npm, "@scope/mypackage"));
    }

    [Fact]
    public void NormalizePackageName_Python_SeparatorsNormalized()
    {
        var a = DependencyConsistencyAnalyzer.NormalizePackageName(DependencyEcosystem.Python, "zope.interface");
        var b = DependencyConsistencyAnalyzer.NormalizePackageName(DependencyEcosystem.Python, "zope-interface");
        var c = DependencyConsistencyAnalyzer.NormalizePackageName(DependencyEcosystem.Python, "zope_interface");
        Assert.Equal(a, b);
        Assert.Equal(a, c);
    }

    [Fact]
    public void BuildVersionGroups_ExactSamePackage_OneGroup()
    {
        var packages = new DependencyPackageInfo[]
        {
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0", manifestPath: "sub/package.json")
        };

        var groups = DependencyConsistencyAnalyzer.BuildVersionGroups(packages);

        Assert.Single(groups);
        Assert.Equal(2, groups[0].Packages.Count);
    }

    [Fact]
    public void BuildSourceGroups_DifferentPackages_DifferentGroups()
    {
        var packages = new DependencyPackageInfo[]
        {
            CreatePackage(DependencyEcosystem.Npm, "lib-a", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "lib-b", "2.0.0")
        };

        var groups = DependencyConsistencyAnalyzer.BuildSourceGroups(packages);

        Assert.Equal(2, groups.Count);
    }

    // --- Helpers ---

    private static AnalysisContext CreateContextWithInventory(DependencyInventoryArtifact inventory)
    {
        var context = new AnalysisContext("test-target", "/tmp/repo", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, inventory));
        return context;
    }

    private static DependencyInventoryArtifact CreateInventory(DependencyPackageInfo[] packages) =>
        new(
            Manifests: [],
            Lockfiles: [],
            Packages: packages,
            PackageSources: [],
            Metrics: new Dictionary<string, string>());

    private static DependencyPackageInfo CreatePackage(
        DependencyEcosystem ecosystem,
        string name,
        string version,
        DependencyScope scope = DependencyScope.Production,
        string manifestPath = "package.json",
        bool isDirect = true) =>
        new(
            ecosystem,
            name,
            version,
            scope,
            manifestPath,
            LockfilePath: null,
            IsDirect: isDirect,
            IsVersionPinned: true,
            IsPrerelease: false);
}

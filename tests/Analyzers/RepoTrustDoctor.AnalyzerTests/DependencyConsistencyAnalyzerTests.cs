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

    // --- TRUST-DEP052 Tests ---

    [Fact]
    public async Task DEP052_SamePackageExactVersion_NoFinding()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0", manifestPath: "sub/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP052");
    }

    [Fact]
    public async Task DEP052_TwoMajorVersions_ReportsFinding()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", manifestPath: "sub/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP052");
        Assert.NotEmpty(finding.Evidence);
        Assert.False(string.IsNullOrWhiteSpace(finding.Recommendation.Message));
        Assert.False(string.IsNullOrWhiteSpace(finding.IdentityKey));
        Assert.Equal(Severity.Low, finding.Severity);
    }

    [Fact]
    public async Task DEP052_ThreeMajorVersions_MediumSeverity()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", manifestPath: "sub-a/package.json"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "3.0.0", manifestPath: "sub-b/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP052");
        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public async Task DEP052_DevelopmentDependency_NoFinding()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0", scope: DependencyScope.Development),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", scope: DependencyScope.Development, manifestPath: "sub/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP052");
    }

    [Fact]
    public async Task DEP052_RangedVersion_Skipped()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "^1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", manifestPath: "sub/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        // ^1.0.0 is a range, not parsed; only one exact version (2.0.0)
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP052");
    }

    [Fact]
    public async Task DEP052_NpmScopedPackage_Normalized()
    {
        var inventory = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "@scope/mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "@SCOPE/mylib", "2.0.0", manifestPath: "sub/package.json")
        ]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP052");
        Assert.Contains("dep052|npm|@scope/mylib", finding.IdentityKey);
    }

    [Fact]
    public async Task DEP052_IdentityKey_StableUnderOrderChanges()
    {
        var inventory1 = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", manifestPath: "sub/package.json")
        ]);
        var inventory2 = CreateInventory([
            CreatePackage(DependencyEcosystem.Npm, "mylib", "2.0.0", manifestPath: "sub/package.json"),
            CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0")
        ]);

        var context1 = CreateContextWithInventory(inventory1);
        var context2 = CreateContextWithInventory(inventory2);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result1 = await analyzer.AnalyzeAsync(context1, CancellationToken.None);
        var result2 = await analyzer.AnalyzeAsync(context2, CancellationToken.None);

        var key1 = result1.Findings.First(f => f.RuleId == "TRUST-DEP052").IdentityKey;
        var key2 = result2.Findings.First(f => f.RuleId == "TRUST-DEP052").IdentityKey;
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void ParseExactMajorVersion_ValidExact()
    {
        Assert.Equal(1, DependencyConsistencyAnalyzer.ParseExactMajorVersion("1.2.3"));
        Assert.Equal(2, DependencyConsistencyAnalyzer.ParseExactMajorVersion("2.0.0"));
        Assert.Equal(3, DependencyConsistencyAnalyzer.ParseExactMajorVersion("v3.1.0"));
    }

    [Fact]
    public void ParseExactMajorVersion_RangesReturnNull()
    {
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion("^1.0.0"));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion("~2.1.0"));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion(">=1.0.0"));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion("[1.2.3]"));
    }

    [Fact]
    public void ParseExactMajorVersion_NonVersionsReturnNull()
    {
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion("latest"));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion(""));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion(null!));
        Assert.Null(DependencyConsistencyAnalyzer.ParseExactMajorVersion("github:user/repo"));
    }

    // --- TRUST-DEP053 Tests ---

    [Fact]
    public async Task DEP053_RegistryVsGit_ReportsFinding()
    {
        var pkg1 = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0");
        var pkg2 = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "git" }, manifestPath: "sub/package.json");

        var inventory = CreateInventory([pkg1, pkg2]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP053");
        Assert.NotEmpty(finding.Evidence);
        Assert.False(string.IsNullOrWhiteSpace(finding.Recommendation.Message));
        Assert.False(string.IsNullOrWhiteSpace(finding.IdentityKey));
        Assert.Contains("dep053|npm|mylib", finding.IdentityKey);
    }

    [Fact]
    public async Task DEP053_RegistryVsPath_ReportsFinding()
    {
        var pkg1 = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0");
        var pkg2 = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "path" }, manifestPath: "sub/package.json");

        var inventory = CreateInventory([pkg1, pkg2]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP053");
    }

    [Fact]
    public async Task DEP053_RegistryVsRegistry_NoFinding()
    {
        var pkg1 = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0");
        var pkg2 = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0", manifestPath: "sub/package.json");

        var inventory = CreateInventory([pkg1, pkg2]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP053");
    }

    [Fact]
    public async Task DEP053_UnknownSource_NoFinding()
    {
        var pkg1 = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "registry" });
        var pkg2 = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "unknown" }, manifestPath: "sub/package.json");

        var inventory = CreateInventory([pkg1, pkg2]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        // unknown vs registry should not trigger by default
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP053");
    }

    [Fact]
    public async Task DEP053_WorkspaceSource_NormalizedToPath()
    {
        var pkg1 = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0");
        var pkg2 = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "workspace" }, manifestPath: "sub/package.json");

        var inventory = CreateInventory([pkg1, pkg2]);
        var context = CreateContextWithInventory(inventory);
        var analyzer = new DependencyConsistencyAnalyzer();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        // workspace is treated as path; should report
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP053");
    }

    [Fact]
    public void GetSourceKind_DefaultsToRegistry()
    {
        var pkg = CreatePackage(DependencyEcosystem.Npm, "mylib", "1.0.0");
        Assert.Equal("registry", DependencyConsistencyAnalyzer.GetSourceKind(pkg));
    }

    [Fact]
    public void GetSourceKind_ReadsMetadata()
    {
        var pkg = CreatePackageWithMetadata(DependencyEcosystem.Npm, "mylib", "1.0.0",
            new Dictionary<string, string> { ["sourceKind"] = "git" });
        Assert.Equal("git", DependencyConsistencyAnalyzer.GetSourceKind(pkg));
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

    private static DependencyPackageInfo CreatePackageWithMetadata(
        DependencyEcosystem ecosystem,
        string name,
        string version,
        IReadOnlyDictionary<string, string> metadata,
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
            IsPrerelease: false,
            Metadata: metadata);
}

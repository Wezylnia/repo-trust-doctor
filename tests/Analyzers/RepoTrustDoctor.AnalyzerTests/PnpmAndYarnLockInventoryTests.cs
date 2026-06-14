using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class PnpmAndYarnLockInventoryTests
{
    [Fact]
    public async Task AnalyzeAsync_PnpmV9Lock_ResolvesRootDependency()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "react", "^19.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), """
        lockfileVersion: '9.0'

        importers:
          .:
            dependencies:
              react:
                specifier: ^19.0.0
                version: 19.1.1
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("19.1.1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("^19.0.0", package.Metadata!["requestedVersion"]);
        Assert.Equal("pnpm-lock", package.Metadata["versionSource"]);
        Assert.Equal("pnpm-lock.yaml", package.LockfilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_PnpmWorkspace_UsesMatchingImporterVersion()
    {
        using var fixture = TemporaryRepository.Create();
        var app = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app")).FullName;
        var admin = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "admin")).FullName;
        WritePackageJson(app, "react", "^19.0.0");
        WritePackageJson(admin, "react", "^18.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), """
        lockfileVersion: '9.0'

        importers:
          packages/app:
            dependencies:
              react:
                specifier: ^19.0.0
                version: 19.1.1
          packages/admin:
            dependencies:
              react:
                specifier: ^18.0.0
                version: 18.3.1
        """);

        var inventory = await AnalyzeAsync(fixture.Path);
        var appPackage = Assert.Single(
            inventory.Packages,
            package => package.ManifestPath == "packages/app/package.json" && package.Name == "react");
        var adminPackage = Assert.Single(
            inventory.Packages,
            package => package.ManifestPath == "packages/admin/package.json" && package.Name == "react");

        Assert.Equal("19.1.1", appPackage.Version);
        Assert.Equal("18.3.1", adminPackage.Version);
    }

    [Fact]
    public async Task AnalyzeAsync_PnpmV5RootDependency_ResolvesScalarVersion()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "left-pad", "^1.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), """
        lockfileVersion: 5.4

        dependencies:
          left-pad: 1.3.0
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("1.3.0", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_YarnV1Lock_ResolvesRequestedSelector()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "lodash", "^4.17.0");
        File.WriteAllText(Path.Combine(fixture.Path, "yarn.lock"), """
        # yarn lockfile v1

        lodash@^4.17.0:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("4.17.21", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("yarn-lock", package.Metadata!["versionSource"]);
    }

    [Fact]
    public async Task AnalyzeAsync_YarnBerryLock_ResolvesNpmProtocolSelector()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "@scope/example", "~2.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "yarn.lock"), """
        __metadata:
          version: 8

        "@scope/example@npm:~2.0.0":
          version: 2.0.7
          resolution: "@scope/example@npm:2.0.7"
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("2.0.7", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_YarnMultipleSelectors_ResolveEachRequestedRange()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "shared", "~1.2.0");
        File.WriteAllText(Path.Combine(fixture.Path, "yarn.lock"), """
        "shared@^1.0.0", "shared@~1.2.0":
          version "1.2.9"
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("1.2.9", package.Version);
    }

    [Fact]
    public async Task AnalyzeAsync_YarnDifferentSelector_DoesNotGuessInstalledVersion()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "shared", "^2.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "yarn.lock"), """
        shared@^1.0.0:
          version "1.9.0"
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("^2.0.0", package.Version);
        Assert.False(package.IsVersionPinned);
        Assert.DoesNotContain("versionSource", package.Metadata!.Keys);
    }

    [Fact]
    public async Task AnalyzeAsync_YarnAlias_UsesDeclaredSelectorAndRealPackageIdentity()
    {
        using var fixture = TemporaryRepository.Create();
        WritePackageJson(fixture.Path, "compat-package", "npm:real-package@^3.0.0");
        File.WriteAllText(Path.Combine(fixture.Path, "yarn.lock"), """
        "compat-package@npm:real-package@^3.0.0":
          version "3.2.1"
        """);

        var package = await AnalyzeSinglePackageAsync(fixture.Path);

        Assert.Equal("real-package", package.Name);
        Assert.Equal("3.2.1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("compat-package", package.Metadata!["declaredName"]);
        Assert.Equal("yarn-lock", package.Metadata["versionSource"]);
    }

    private static void WritePackageJson(string directory, string packageName, string version)
    {
        File.WriteAllText(Path.Combine(directory, "package.json"), $$"""
        {
          "dependencies": {
            "{{packageName}}": "{{version}}"
          }
        }
        """);
    }

    private static async Task<DependencyPackageInfo> AnalyzeSinglePackageAsync(string repositoryPath) =>
        Assert.Single((await AnalyzeAsync(repositoryPath)).Packages);

    private static async Task<DependencyInventoryArtifact> AnalyzeAsync(string repositoryPath)
    {
        var result = await new DependencyInventoryAnalyzer().AnalyzeAsync(
            new AnalysisContext(repositoryPath, repositoryPath, AnalysisDepth.Standard),
            CancellationToken.None);
        return Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey).Value);
    }
}

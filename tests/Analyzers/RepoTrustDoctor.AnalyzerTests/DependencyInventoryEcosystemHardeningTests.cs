using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryEcosystemHardeningTests
{
    [Fact]
    public async Task AnalyzeAsync_MixLock_ResolvesHexConstraintWithoutFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "mix.exs"), """
        defp deps do
          [{:ecto_sql, "~> 3.11"}]
        end
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "mix.lock"), """
        %{
          "ecto_sql": {:hex, :ecto_sql, "3.13.2", "checksum", [:mix], [], "hexpm", "outer"}
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, item => item.Name == "ecto_sql");

        Assert.Equal("3.13.2", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("mix.lock", package.LockfilePath);
        Assert.Equal("mix.lock", package.Metadata!["versionSource"]);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP041");
    }

    [Fact]
    public async Task AnalyzeAsync_InternalHexPathDependency_DoesNotReportRemoteSourceRisk()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "apps", "internal"));
        File.WriteAllText(Path.Combine(fixture.Path, "mix.exs"), """
        defp deps do
          [{:internal, path: "./apps/internal"}]
        end
        """);

        var result = await AnalyzeAsync(fixture.Path);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP042");
    }

    [Fact]
    public async Task AnalyzeAsync_NonObjectPackageJson_IsSkippedWithoutFailing()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(fixture.Path, "package.json"),
            "\"This package has moved to another repository\"");

        var result = await AnalyzeAsync(fixture.Path);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        Assert.Contains(result.Warnings!, warning => warning.Contains("root is not an object", StringComparison.Ordinal));
        Assert.Empty(GetInventory(result).Manifests);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP001");
    }

    [Fact]
    public async Task AnalyzeAsync_SwiftLibraryWithoutResolved_DoesNotReportApplicationRisk()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Package.swift"), """
        let package = Package(
            products: [
                .library(name: "Example", targets: ["Example"])
            ],
            dependencies: [
                .package(url: "https://github.com/example/lib", from: "1.0.0")
            ]
        )
        """);

        var result = await AnalyzeAsync(fixture.Path);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP043");
    }

    [Fact]
    public async Task AnalyzeAsync_MultilineSwiftDependency_IsRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Package.swift"), """
        let package = Package(
            dependencies: [
                .package(
                    url: "https://github.com/apple/swift-collections.git",
                    exact: "1.1.4"
                )
            ]
        )
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(
            GetInventory(result).Packages,
            item => item.Name == "https://github.com/apple/swift-collections.git");

        Assert.Equal("1.1.4", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_LargeCmakeManifest_IsStreamedAndDetected()
    {
        using var fixture = TemporaryRepository.Create();
        var content = new string('#', 600 * 1024) + Environment.NewLine +
                      "find_package(OpenSSL REQUIRED)" + Environment.NewLine;
        File.WriteAllText(Path.Combine(fixture.Path, "CMakeLists.txt"), content);

        var result = await AnalyzeAsync(fixture.Path);
        var inventory = GetInventory(result);

        Assert.Contains(inventory.Manifests, manifest =>
            manifest.Ecosystem == DependencyEcosystem.Cpp &&
            manifest.Kind == "CMakeLists.txt");
        Assert.Empty(result.Warnings ?? []);
    }

    private static Task<AnalyzerResult> AnalyzeAsync(string path) =>
        new DependencyInventoryAnalyzer().AnalyzeAsync(
            new AnalysisContext(path, path, AnalysisDepth.Standard),
            CancellationToken.None);

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result) =>
        Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey).Value);
}

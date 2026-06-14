using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CargoWorkspaceDependencyTests
{
    [Fact]
    public async Task AnalyzeAsync_InheritedWorkspaceDependency_UsesWorkspaceVersion()
    {
        using var fixture = TemporaryRepository.Create();
        var memberDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "crates", "api")).FullName;
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/api"]

        [workspace.dependencies]
        serde = "1.0.219"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), """
        version = 4

        [[package]]
        name = "serde"
        version = "1.0.219"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """);
        File.WriteAllText(Path.Combine(memberDirectory, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies]
        serde = { workspace = true, features = ["derive"] }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "serde");

        Assert.Equal("1.0.219", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("true", package.Metadata!["workspaceInherited"]);
        Assert.Equal("Cargo.toml", package.Metadata["workspaceDefinitionPath"]);
        Assert.Equal("crates/api/Cargo.toml", package.ManifestPath);
    }

    [Fact]
    public async Task AnalyzeAsync_UnusedWorkspaceDefinition_DoesNotBecomePackage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = []

        [workspace.dependencies]
        unused = "9.9.9"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");

        var result = await AnalyzeAsync(fixture.Path);

        Assert.DoesNotContain(GetInventory(result).Packages, item => item.Name == "unused");
    }

    [Fact]
    public async Task AnalyzeAsync_InheritedSimpleVersion_IsPreservedWithoutLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        var memberDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "crates", "api")).FullName;
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/api"]

        [workspace.dependencies]
        serde = "=1.0.219"
        """);
        File.WriteAllText(Path.Combine(memberDirectory, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies]
        serde = { workspace = true }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "serde");

        Assert.Equal("1.0.219", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("true", package.Metadata!["workspaceInherited"]);
        Assert.Equal("=1.0.219", package.Metadata["requestedVersion"]);
        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId == "TRUST-DEP029" &&
                       finding.Evidence.Any(evidence => evidence.FilePath == "crates/api/Cargo.toml"));
    }

    [Fact]
    public async Task AnalyzeAsync_WorkspaceDependencySubtable_ResolvesAlias()
    {
        using var fixture = TemporaryRepository.Create();
        var memberDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "crates", "api")).FullName;
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/api"]

        [workspace.dependencies.http_alias]
        package = "http"
        version = "1"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), """
        version = 4

        [[package]]
        name = "http"
        version = "1.3.1"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """);
        File.WriteAllText(Path.Combine(memberDirectory, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies.http_alias]
        workspace = true
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "http");

        Assert.Equal("http_alias", package.Metadata!["manifestAlias"]);
        Assert.Equal("1.3.1", package.Version);
        Assert.Equal("true", package.Metadata["workspaceInherited"]);
    }

    [Fact]
    public async Task AnalyzeAsync_InheritedPath_IsResolvedFromWorkspaceRoot()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "crates", "shared"));
        var memberDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "crates", "api")).FullName;
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/api", "crates/shared"]

        [workspace.dependencies]
        shared = { path = "crates/shared" }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(memberDirectory, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies]
        shared = { workspace = true }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "shared");

        Assert.Equal("path", package.Metadata!["sourceKind"]);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP028");
    }

    [Fact]
    public async Task AnalyzeAsync_MultipleLockedMajors_UsesRequestedCompatibleVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies]
        http = "1"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), """
        version = 4

        [[package]]
        name = "http"
        version = "0.2.12"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "http"
        version = "1.3.1"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "http");

        Assert.Equal("1.3.1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("Cargo.lock", package.LockfilePath);
        Assert.Equal("1", package.Metadata!["requestedVersion"]);
    }

    [Theory]
    [InlineData("~1.2", "1.2.9")]
    [InlineData("0.2", "0.2.8")]
    [InlineData(">=1.5, <2", "1.8.0")]
    public async Task AnalyzeAsync_CargoRequirement_SelectsSingleCompatibleLockCandidate(
        string requirement,
        string expected)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), $$"""
        [package]
        name = "api"

        [dependencies]
        sample = "{{requirement}}"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), """
        version = 4

        [[package]]
        name = "sample"
        version = "0.2.8"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "sample"
        version = "1.2.9"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "sample"
        version = "1.8.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "sample"
        version = "2.0.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "sample");

        Assert.Equal(expected, package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_PrereleaseRequirement_UsesSemanticIdentifierOrdering()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "api"

        [dependencies]
        sample = ">=1.0.0-rc.3, <1.0.0"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), """
        version = 4

        [[package]]
        name = "sample"
        version = "1.0.0-rc.2"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "sample"
        version = "1.0.0-rc.10"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "sample");

        Assert.Equal("1.0.0-rc.10", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    private static Task<AnalyzerResult> AnalyzeAsync(string path) =>
        new DependencyInventoryAnalyzer().AnalyzeAsync(
            new AnalysisContext(path, path, AnalysisDepth.Standard),
            CancellationToken.None);

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result) =>
        Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey).Value);
}

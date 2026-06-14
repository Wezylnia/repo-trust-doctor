using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class PythonRequirementGraphTests
{
    [Fact]
    public async Task AnalyzeAsync_RequirementInclude_AddsPackagesAndIncludedManifest()
    {
        using var fixture = TemporaryRepository.Create();
        var requirementsDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "requirements")).FullName;
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "-r requirements/base.txt");
        File.WriteAllText(
            Path.Combine(requirementsDirectory, "base.txt"),
            "requests[socks]==2.31.0");

        var result = await AnalyzeAsync(fixture.Path);
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages);

        Assert.Equal("requests", package.Name);
        Assert.Equal("2.31.0", package.Version);
        Assert.Equal("requirements/base.txt", package.ManifestPath);
        Assert.Contains(
            inventory.Manifests,
            manifest => manifest.FilePath == "requirements/base.txt" &&
                        manifest.Kind == "requirements-include");
    }

    [Fact]
    public async Task AnalyzeAsync_ExactConstraint_ResolvesRequestedRange()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "-c constraints.txt" + Environment.NewLine + "flask>=3.0");
        File.WriteAllText(
            Path.Combine(fixture.Path, "constraints.txt"),
            "Flask==3.1.0");

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("flask", package.Name);
        Assert.Equal("3.1.0", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("constraints.txt", package.Metadata!["constraintPath"]);
        Assert.Equal("flask>=3.0", package.Metadata["requestedRequirement"]);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_ArbitraryExactRequirement_IsPinned()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "internal-package===2026.06-company1");

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("2026.06-company1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_RequirementIncludeOutsideRepository_IsSkipped()
    {
        using var fixture = TemporaryRepository.Create();
        var outsideName = $"outside-{Guid.NewGuid():N}.txt";
        var outsidePath = Path.Combine(Path.GetDirectoryName(fixture.Path)!, outsideName);
        File.WriteAllText(outsidePath, "unsafe-package==1.0.0");
        try
        {
            File.WriteAllText(
                Path.Combine(fixture.Path, "requirements.txt"),
                $"-r ../{outsideName}");

            var result = await AnalyzeAsync(fixture.Path);

            Assert.Empty(GetInventory(result).Packages);
            Assert.Contains(
                result.Warnings ?? [],
                warning => warning.Contains("outside the repository", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(outsidePath);
        }
    }

    [Fact]
    public async Task AnalyzeAsync_CyclicIncludes_TerminateAndDeduplicatePackages()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "-r base.txt" + Environment.NewLine + "root-package==1.0.0");
        File.WriteAllText(
            Path.Combine(fixture.Path, "base.txt"),
            "-r requirements.txt" + Environment.NewLine + "base-package==2.0.0");

        var result = await AnalyzeAsync(fixture.Path);
        var packages = GetInventory(result).Packages;

        Assert.Equal(2, packages.Count);
        Assert.Single(packages, package => package.Name == "root-package");
        Assert.Single(packages, package => package.Name == "base-package");
    }

    [Fact]
    public async Task AnalyzeAsync_NestedInclude_IsResolvedRelativeToIncludingFile()
    {
        using var fixture = TemporaryRepository.Create();
        var nestedDirectory = Directory.CreateDirectory(
            Path.Combine(fixture.Path, "requirements", "nested")).FullName;
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "-r requirements/base.txt");
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements", "base.txt"),
            "-r nested/service.txt");
        File.WriteAllText(
            Path.Combine(nestedDirectory, "service.txt"),
            "httpx==0.28.1");

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("httpx", package.Name);
        Assert.Equal("requirements/nested/service.txt", package.ManifestPath);
    }

    [Fact]
    public async Task AnalyzeAsync_RequirementIncludedByConstraintFile_RemainsInstallable()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(fixture.Path, "requirements.txt"),
            "-c constraints.txt");
        File.WriteAllText(
            Path.Combine(fixture.Path, "constraints.txt"),
            "-r runtime.txt");
        File.WriteAllText(
            Path.Combine(fixture.Path, "runtime.txt"),
            "fastapi==0.115.0");

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("fastapi", package.Name);
        Assert.Equal("runtime.txt", package.ManifestPath);
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

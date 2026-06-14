using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class PythonDependencyInventoryTests
{
    [Fact]
    public async Task AnalyzeAsync_LockfileInSiblingProject_DoesNotCoverIndependentManifest()
    {
        using var fixture = TemporaryRepository.Create();
        var serviceA = Directory.CreateDirectory(Path.Combine(fixture.Path, "services", "a")).FullName;
        var serviceB = Directory.CreateDirectory(Path.Combine(fixture.Path, "services", "b")).FullName;
        File.WriteAllText(Path.Combine(serviceA, "pyproject.toml"), """
        [tool.poetry.dependencies]
        python = "^3.12"
        requests = "^2.31"
        """);
        File.WriteAllText(Path.Combine(serviceA, "poetry.lock"), """
        [[package]]
        name = "requests"
        version = "2.32.4"
        """);
        File.WriteAllText(Path.Combine(serviceB, "requirements.txt"), "flask>=3.0");

        var result = await AnalyzeAsync(fixture.Path);

        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-DEP003");
        Assert.Equal("services/b/requirements.txt", Assert.Single(finding.Evidence).FilePath);
        Assert.DoesNotContain(
            result.Findings,
            item => item.RuleId == "TRUST-DEP003" &&
                    item.Evidence.Any(evidence => evidence.FilePath == "services/a/pyproject.toml"));
    }

    [Fact]
    public async Task AnalyzeAsync_PoetryLock_ResolvesRequestedVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [tool.poetry.dependencies]
        python = "^3.12"
        requests = "^2.31"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "poetry.lock"), """
        [[package]]
        name = "requests"
        version = "2.32.4"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "requests");

        Assert.Equal("2.32.4", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("poetry.lock", package.LockfilePath);
        Assert.Equal("^2.31", package.Metadata!["requestedVersion"]);
        Assert.DoesNotContain(result.Findings, item => item.RuleId == "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_UvLock_ResolvesPep503NormalizedPackageName()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [project]
        dependencies = ["typing_extensions>=4.10"]
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "uv.lock"), """
        [[package]]
        name = "typing-extensions"
        version = "4.14.0"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "typing_extensions");

        Assert.Equal("4.14.0", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("uv.lock", package.LockfilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_PipfileLock_ResolvesProductionAndDevelopmentPackages()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile"), """
        [packages]
        requests = "*"
        [dev-packages]
        pytest = ">=8"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile.lock"), """
        {
          "default": {
            "requests": { "version": "==2.32.4" }
          },
          "develop": {
            "pytest": { "version": "==8.4.0" }
          }
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var packages = GetInventory(result).Packages;
        var requests = Assert.Single(packages, item => item.Name == "requests");
        var pytest = Assert.Single(packages, item => item.Name == "pytest");

        Assert.Equal("2.32.4", requests.Version);
        Assert.Equal(DependencyScope.Production, requests.Scope);
        Assert.Equal("8.4.0", pytest.Version);
        Assert.Equal(DependencyScope.Development, pytest.Scope);
        Assert.All([requests, pytest], package => Assert.True(package.IsVersionPinned));
        Assert.DoesNotContain(result.Findings, item => item.RuleId == "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_ExactPipfileVersion_IsPinnedWithoutLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile"), """
        [packages]
        requests = "==2.31.0"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("2.31.0", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, item => item.RuleId == "TRUST-DEP009");
        Assert.Contains(result.Findings, item => item.RuleId == "TRUST-DEP003");
    }

    [Fact]
    public async Task AnalyzeAsync_RequirementExtras_PreserveRegistryPackageIdentity()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "requirements.txt"), "requests[socks]==2.31.0");

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("requests", package.Name);
        Assert.Equal("2.31.0", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, item => item.RuleId == "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_LargePythonLockfile_IsNotLimitedByManifestTextBudget()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [tool.poetry.dependencies]
        python = "^3.12"
        requests = "^2.31"
        """);
        File.WriteAllText(
            Path.Combine(fixture.Path, "poetry.lock"),
            new string('#', 600 * 1024) + Environment.NewLine + """
            [[package]]
            name = "requests"
            version = "2.32.4"
            """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "requests");

        Assert.Equal("2.32.4", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Warnings ?? [], warning => warning.Contains("too large", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnalyzeAsync_InvalidPoetryLock_FallsBackToValidUvLock()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [project]
        dependencies = ["requests>=2.31"]
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "poetry.lock"), "{ invalid");
        File.WriteAllText(Path.Combine(fixture.Path, "uv.lock"), """
        [[package]]
        name = "requests"
        version = "2.32.4"
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("2.32.4", package.Version);
        Assert.Equal("uv.lock", package.LockfilePath);
    }

    private static Task<AnalyzerResult> AnalyzeAsync(string path) =>
        new DependencyInventoryAnalyzer().AnalyzeAsync(
            new AnalysisContext(path, path, AnalysisDepth.Standard),
            CancellationToken.None);

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result) =>
        Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey).Value);
}

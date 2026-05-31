using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReturnsCompletedWithNoFindings_ForEmptyRepository()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmManifestWithoutLockfile_ReportsDep001()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP001");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("package.json", evidence.FilePath);
    }

    [Theory]
    [InlineData("package-lock.json")]
    [InlineData("pnpm-lock.yaml")]
    [InlineData("yarn.lock")]
    public async Task AnalyzeAsync_NpmManifestWithLockfile_DoesNotReportDep001(string lockfileName)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, lockfileName), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetProjectWithoutLockfile_ReportsDep002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "MyProject.csproj"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP002");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.Medium, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("MyProject.csproj", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetProjectWithLockfile_DoesNotReportDep002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "MyProject.csproj"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}

using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryResilienceTests
{
    [Fact]
    public async Task AnalyzeAsync_CollectorFailure_DiscardsPartialStateAndContinues()
    {
        using var fixture = TemporaryRepository.Create();
        var analyzer = new DependencyInventoryAnalyzer(
            [new FailingCollector(), new SuccessfulCollector()]);

        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        var artifact = Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!).Value);
        var package = Assert.Single(artifact.Packages);
        Assert.Equal("successful-package", package.Name);
        Assert.DoesNotContain(
            artifact.Packages,
            candidate => candidate.Name == "partial-package");
        Assert.Contains(
            result.Warnings!,
            warning => warning.Contains(
                nameof(FailingCollector),
                StringComparison.Ordinal));
        Assert.Equal("2", result.Metrics!["dependency.collector.attempted.count"]);
        Assert.Equal("1", result.Metrics["dependency.collector.completed.count"]);
        Assert.Equal("1", result.Metrics["dependency.collector.failed.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_CollectorCancellation_IsNotContained()
    {
        using var fixture = TemporaryRepository.Create();
        var analyzer = new DependencyInventoryAnalyzer(
            [new CancelledCollector()]);

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            analyzer.AnalyzeAsync(
                new AnalysisContext(
                    fixture.Path,
                    fixture.Path,
                    AnalysisDepth.Standard),
                CancellationToken.None));
    }

    private sealed class FailingCollector : IDependencyInventoryCollector
    {
        public void Collect(
            AnalysisContext context,
            DependencyInventoryState state,
            CancellationToken cancellationToken)
        {
            state.Packages.Add(CreatePackage("partial-package"));
            throw new InvalidDataException("simulated parser failure");
        }
    }

    private sealed class SuccessfulCollector : IDependencyInventoryCollector
    {
        public void Collect(
            AnalysisContext context,
            DependencyInventoryState state,
            CancellationToken cancellationToken)
        {
            state.Packages.Add(CreatePackage("successful-package"));
        }
    }

    private sealed class CancelledCollector : IDependencyInventoryCollector
    {
        public void Collect(
            AnalysisContext context,
            DependencyInventoryState state,
            CancellationToken cancellationToken)
        {
            throw new OperationCanceledException();
        }
    }

    private static DependencyPackageInfo CreatePackage(string name) =>
        new(
            DependencyEcosystem.Npm,
            name,
            "1.0.0",
            DependencyScope.Production,
            "package.json",
            "package-lock.json",
            true,
            true,
            false);
}

using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;

namespace RepoTrustDoctor.UnitTests;

public sealed class DefaultRepositoryScanRunnerTests
{
    [Fact]
    public async Task RunAsync_CompletesFastStaticScan_ForLocalRepository()
    {
        using var fixture = TemporaryDirectory.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), """
        # Test Project

        ## Installation

        dotnet tool install example

        ## Usage

        example scan .
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "LICENSE"), "Apache-2.0");
        File.WriteAllText(Path.Combine(fixture.Path, "SECURITY.md"), "Report vulnerabilities privately.");

        var scan = await new DefaultRepositoryScanRunner().RunAsync(
            new ScanRequestOptions(fixture.Path, AnalysisDepth.Fast, TrustProfile.ProductionDependency),
            CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, scan.Status);
        Assert.Equal(AnalysisDepth.Fast, scan.Depth);
        Assert.Contains(scan.Modules, module => module.ModuleId == "repository-health");
    }

    [Fact]
    public async Task RunAsync_ReusesConfiguredAnalyzerInstancesAcrossScans()
    {
        using var fixture = TemporaryDirectory.Create();
        var analyzer = new CountingAnalyzer();
        var runner = new DefaultRepositoryScanRunner([analyzer]);
        var options = new ScanRequestOptions(
            fixture.Path,
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency);

        await runner.RunAsync(options, CancellationToken.None);
        await runner.RunAsync(options, CancellationToken.None);

        Assert.Equal(2, analyzer.CallCount);
    }

    private sealed class CountingAnalyzer : IRepositoryAnalyzer
    {
        public int CallCount { get; private set; }

        public string Id => "counting-analyzer";

        public string DisplayName => "Counting Analyzer";

        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

        public IReadOnlyCollection<string> DependsOn => [];

        public AnalyzerExecutionSafety ExecutionSafety =>
            AnalyzerExecutionSafety.StaticOnly;

        public TimeSpan Timeout => TimeSpan.FromSeconds(1);

        public IReadOnlyCollection<RuleMetadata> Rules => [];

        public Task<AnalyzerResult> AnalyzeAsync(
            AnalysisContext context,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(AnalyzerResult.Completed([]));
        }
    }
}

using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.UnitTests;

public sealed class ScanOrchestratorArtifactDependencyTests
{
    [Fact]
    public void Constructor_OrdersAnalyzers_ByAnalyzerIdDependency()
    {
        var analyzerA = new StubAnalyzer("analyzer-a", dependsOn: []);
        var analyzerB = new StubAnalyzer("analyzer-b", dependsOn: ["analyzer-a"]);

        var orchestrator = CreateOrchestrator([analyzerB, analyzerA]);

        var orderedIds = GetOrderedAnalyzerIds(orchestrator);
        Assert.Equal(["analyzer-a", "analyzer-b"], orderedIds);
    }

    [Fact]
    public void Constructor_OrdersAnalyzers_ByArtifactKeyDependency()
    {
        var producer = new StubAnalyzer("dependency-inventory",
            producesArtifacts: [DependencyInventoryArtifact.ArtifactKey]);
        var consumer = new StubAnalyzer("dependency-metadata",
            dependsOn: [DependencyInventoryArtifact.ArtifactKey]);

        var orchestrator = CreateOrchestrator([consumer, producer]);

        var orderedIds = GetOrderedAnalyzerIds(orchestrator);
        Assert.Equal(["dependency-inventory", "dependency-metadata"], orderedIds);
    }

    [Fact]
    public void Constructor_Throws_WhenDuplicateArtifactProducers()
    {
        var producerA = new StubAnalyzer("producer-a",
            producesArtifacts: [DependencyInventoryArtifact.ArtifactKey]);
        var producerB = new StubAnalyzer("producer-b",
            producesArtifacts: [DependencyInventoryArtifact.ArtifactKey]);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateOrchestrator([producerA, producerB]));

        Assert.Contains("produced by more than one analyzer", ex.Message);
    }

    [Fact]
    public void Constructor_Throws_WhenUnknownArtifactDependency()
    {
        var consumer = new StubAnalyzer("consumer",
            dependsOn: ["unknown-artifact"]);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateOrchestrator([consumer]));

        Assert.Contains("depends on unknown analyzer or artifact", ex.Message);
    }

    [Fact]
    public void Constructor_Throws_WhenCircularDependencyThroughArtifactKeys()
    {
        var analyzerA = new StubAnalyzer("analyzer-a",
            dependsOn: [ArtifactKeys.ArtifactB],
            producesArtifacts: [ArtifactKeys.ArtifactA]);
        var analyzerB = new StubAnalyzer("analyzer-b",
            dependsOn: [ArtifactKeys.ArtifactA],
            producesArtifacts: [ArtifactKeys.ArtifactB]);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CreateOrchestrator([analyzerA, analyzerB]));

        Assert.Contains("dependency cycle", ex.Message);
    }

    [Fact]
    public void Constructor_AllowsAnalyzerWithoutArtifacts()
    {
        var analyzer = new StubAnalyzer("simple-analyzer", dependsOn: []);

        var orchestrator = CreateOrchestrator([analyzer]);

        var orderedIds = GetOrderedAnalyzerIds(orchestrator);
        Assert.Equal(["simple-analyzer"], orderedIds);
    }

    [Fact]
    public void Constructor_PreservesDeterministicOrder()
    {
        var analyzers = new List<StubAnalyzer>();
        for (var i = 0; i < 100; i++)
        {
            analyzers.Add(new StubAnalyzer($"analyzer-{i:D3}", dependsOn: []));
        }

        var run1 = GetOrderedAnalyzerIds(CreateOrchestrator(analyzers));
        var run2 = GetOrderedAnalyzerIds(CreateOrchestrator(analyzers));

        Assert.Equal(run1, run2);
    }

    private static ScanOrchestrator CreateOrchestrator(IEnumerable<IRepositoryAnalyzer> analyzers)
    {
        return new ScanOrchestrator(
            analyzers,
            new AnalyzerExecutor(),
            new TrustScorer());
    }

    private static IReadOnlyList<string> GetOrderedAnalyzerIds(ScanOrchestrator orchestrator)
    {
        // Use reflection to access the private analyzers field for testing ordering
        var field = typeof(ScanOrchestrator).GetField("analyzers",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var analyzers = (IReadOnlyList<IRepositoryAnalyzer>)field!.GetValue(orchestrator)!;
        return analyzers.Select(a => a.Id).ToArray();
    }

    private static class ArtifactKeys
    {
        public const string ArtifactA = "test.artifact-a";
        public const string ArtifactB = "test.artifact-b";
    }

    private sealed class StubAnalyzer : IRepositoryAnalyzer
    {
        private readonly string id;
        private readonly IReadOnlyCollection<string> dependsOn;
        private readonly IReadOnlyCollection<string> producesArtifacts;

        public StubAnalyzer(
            string id,
            IReadOnlyCollection<string>? dependsOn = null,
            IReadOnlyCollection<string>? producesArtifacts = null)
        {
            this.id = id;
            this.dependsOn = dependsOn ?? [];
            this.producesArtifacts = producesArtifacts ?? [];
        }

        public string Id => id;
        public string DisplayName => id;
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => dependsOn;
        public IReadOnlyCollection<string> ProducesArtifacts => producesArtifacts;
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public IReadOnlyCollection<RuleMetadata> Rules => [];
        public TimeSpan Timeout => TimeSpan.FromSeconds(1);

        public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
        {
            return Task.FromResult(AnalyzerResult.Completed([]));
        }
    }
}

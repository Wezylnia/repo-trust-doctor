using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.UnitTests;

public sealed class AnalyzerInfrastructureTests
{
    [Fact]
    public void AllAnalyzers_ExposeNonEmptyRuleMetadata()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();
        var artifactOnlyAnalyzers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "dependency-metadata"
        };

        foreach (var analyzer in analyzers)
        {
            if (!artifactOnlyAnalyzers.Contains(analyzer.Id))
            {
                Assert.NotEmpty(analyzer.Rules);
            }

            foreach (var rule in analyzer.Rules)
            {
                Assert.False(string.IsNullOrWhiteSpace(rule.RuleId), $"Analyzer '{analyzer.Id}' has a rule with empty RuleId.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Title), $"Rule '{rule.RuleId}' has empty Title.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Description), $"Rule '{rule.RuleId}' has empty Description.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Recommendation), $"Rule '{rule.RuleId}' has empty Recommendation.");
            }
        }
    }

    [Fact]
    public void AllAnalyzers_HaveUniqueRuleIds()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();

        var allRuleIds = analyzers.SelectMany(a => a.Rules).Select(r => r.RuleId).ToArray();
        var unique = new HashSet<string>(allRuleIds, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(allRuleIds.Length, unique.Count);
    }

    [Fact]
    public void ScanOrchestrator_ThrowsOnDuplicateAnalyzerId()
    {
        var analyzer1 = new RepositoryHealthAnalyzer();
        var analyzer2 = new RepositoryHealthAnalyzer();

        Assert.Throws<InvalidOperationException>(() =>
            new ScanOrchestrator([analyzer1, analyzer2], new AnalyzerExecutor(), new TrustScorer()));
    }

    [Fact]
    public void ScanOrchestrator_ThrowsOnDuplicateRuleId()
    {
        var analyzer1 = new FakeAnalyzerWithRule("analyzer-a", "TRUST-DUP001");
        var analyzer2 = new FakeAnalyzerWithRule("analyzer-b", "TRUST-DUP001");

        Assert.Throws<InvalidOperationException>(() =>
            new ScanOrchestrator([analyzer1, analyzer2], new AnalyzerExecutor(), new TrustScorer()));
    }

    [Fact]
    public void ScanOrchestrator_ThrowsOnEmptyAnalyzerId()
    {
        var analyzer = new FakeAnalyzerWithRule("", "TRUST-OK001");

        Assert.Throws<InvalidOperationException>(() =>
            new ScanOrchestrator([analyzer], new AnalyzerExecutor(), new TrustScorer()));
    }

    [Fact]
    public async Task AnalyzerExecutor_TimedOutAnalyzer_ReturnsTimedOutStatus()
    {
        var slowAnalyzer = new SlowAnalyzer(delayMs: 5000, timeoutMs: 100);
        var executor = new AnalyzerExecutor();
        var context = new AnalysisContext(".", ".", AnalysisDepth.Fast);

        var result = await executor.ExecuteAsync(slowAnalyzer, context, CancellationToken.None);

        Assert.Equal(ModuleStatus.TimedOut, result.Module.Status);
        Assert.Empty(result.Result.Findings);
    }

    [Fact]
    public async Task ScanOrchestrator_TimedOutAnalyzer_CannotProduceSafeDecision()
    {
        using var directory = TemporaryDirectory.Create();
        var slowAnalyzer = new SlowAnalyzer(delayMs: 5000, timeoutMs: 50);
        var orchestrator = new ScanOrchestrator([slowAnalyzer], new AnalyzerExecutor(), new TrustScorer());

        var scan = await orchestrator.RunAsync(
            ".",
            directory.Path,
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            CancellationToken.None);

        Assert.Equal(ModuleStatus.CompletedWithWarnings, scan.Status);
        Assert.Equal(FinalDecisionKind.NeedsManualReview, scan.Score.Decision.Kind);
        Assert.Equal(70, Assert.Single(scan.Score.Categories).Score);
        Assert.Contains(scan.Score.Decision.Reasons, reason => reason.Contains("timed out", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnalyzerExecutor_WarningResult_ReturnsCompletedWithWarningsAndModuleMessage()
    {
        var analyzer = new WarningAnalyzer();
        var executor = new AnalyzerExecutor();
        var context = new AnalysisContext(".", ".", AnalysisDepth.Fast);

        var result = await executor.ExecuteAsync(analyzer, context, CancellationToken.None);

        Assert.Equal(ModuleStatus.CompletedWithWarnings, result.Module.Status);
        Assert.Contains("scope was truncated", result.Module.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal("10", result.Module.Metrics!["analyzed.count"]);
        Assert.Contains("scope was truncated", result.Module.Warnings!);
    }

    [Fact]
    public void AllAnalyzers_HavePositiveTimeout()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();

        foreach (var analyzer in analyzers)
        {
            Assert.True(analyzer.Timeout > TimeSpan.Zero, $"Analyzer '{analyzer.Id}' has zero or negative timeout.");
        }
    }

    [Fact]
    public void DefaultScanAnalyzers_IncludeAutomationAnalyzersForEveryActiveProfile()
    {
        var analyzerIds = DefaultRepositoryScanRunner.CreateAnalyzers()
            .Select(analyzer => analyzer.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in TrustProfileCatalog.ActiveProfiles)
        {
            Assert.Contains("github-actions-basic", analyzerIds);
            Assert.Contains("docker-basic", analyzerIds);
            Assert.True(TrustProfileCatalog.IsActive(profile));
        }
    }

    [Fact]
    public async Task ScanOrchestrator_RunsDependenciesBeforeDependents()
    {
        var dependent = new FakeAnalyzerWithRule("a-dependent", "TRUST-ORDER002", ["z-producer"]);
        var producer = new FakeAnalyzerWithRule("z-producer", "TRUST-ORDER001");
        var orchestrator = new ScanOrchestrator([dependent, producer], new AnalyzerExecutor(), new TrustScorer());

        var scan = await orchestrator.RunAsync(".", ".", AnalysisDepth.Fast, TrustProfile.Personal, CancellationToken.None);

        Assert.Collection(
            scan.Modules,
            module => Assert.Equal("z-producer", module.ModuleId),
            module => Assert.Equal("a-dependent", module.ModuleId));
    }

    private sealed class FakeAnalyzerWithRule : IRepositoryAnalyzer
    {
        private readonly string id;
        private readonly string ruleId;
        private readonly IReadOnlyCollection<string> dependsOn;

        public FakeAnalyzerWithRule(string id, string ruleId, IReadOnlyCollection<string>? dependsOn = null)
        {
            this.id = id;
            this.ruleId = ruleId;
            this.dependsOn = dependsOn ?? [];
        }

        public string Id => id;
        public string DisplayName => id;
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => dependsOn;
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new(ruleId, "Fake rule", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "Fake", "Fake")
        ];

        public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken) =>
            Task.FromResult(AnalyzerResult.Completed([]));
    }

    private sealed class SlowAnalyzer : IRepositoryAnalyzer
    {
        private readonly int delayMs;
        private readonly int timeoutMs;

        public SlowAnalyzer(int delayMs, int timeoutMs)
        {
            this.delayMs = delayMs;
            this.timeoutMs = timeoutMs;
        }

        public string Id => "slow-analyzer";
        public string DisplayName => "Slow Analyzer";
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromMilliseconds(timeoutMs);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new("TRUST-SLOW001", "Slow rule", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "Slow", "Wait")
        ];

        public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
        {
            await Task.Delay(delayMs, cancellationToken);
            return AnalyzerResult.Completed([]);
        }
    }

    private sealed class WarningAnalyzer : IRepositoryAnalyzer
    {
        public string Id => "warning-analyzer";
        public string DisplayName => "Warning Analyzer";
        public AnalysisCategory Category => AnalysisCategory.Codebase;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new("TRUST-WARN001", "Warning rule", AnalysisCategory.Codebase, Severity.Info, Confidence.High, "Warning", "Review")
        ];

        public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken) =>
            Task.FromResult(AnalyzerResult.Completed(
                [],
                metrics: new Dictionary<string, string> { ["analyzed.count"] = "10" },
                warnings: ["scope was truncated"]));
    }
}

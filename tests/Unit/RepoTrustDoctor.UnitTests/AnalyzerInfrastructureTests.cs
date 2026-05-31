using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.UnitTests;

public sealed class AnalyzerInfrastructureTests
{
    [Fact]
    public void AllAnalyzers_ExposeNonEmptyRuleMetadata()
    {
        IRepositoryAnalyzer[] analyzers =
        [
            new RepositoryHealthAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer()
        ];

        foreach (var analyzer in analyzers)
        {
            Assert.NotEmpty(analyzer.Rules);
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
        IRepositoryAnalyzer[] analyzers =
        [
            new RepositoryHealthAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer()
        ];

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
    public void AllAnalyzers_HavePositiveTimeout()
    {
        IRepositoryAnalyzer[] analyzers =
        [
            new RepositoryHealthAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer()
        ];

        foreach (var analyzer in analyzers)
        {
            Assert.True(analyzer.Timeout > TimeSpan.Zero, $"Analyzer '{analyzer.Id}' has zero or negative timeout.");
        }
    }

    private sealed class FakeAnalyzerWithRule : IRepositoryAnalyzer
    {
        private readonly string id;
        private readonly string ruleId;

        public FakeAnalyzerWithRule(string id, string ruleId)
        {
            this.id = id;
            this.ruleId = ruleId;
        }

        public string Id => id;
        public string DisplayName => id;
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
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
}

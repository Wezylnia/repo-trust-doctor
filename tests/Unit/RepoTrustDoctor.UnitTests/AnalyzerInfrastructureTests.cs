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
    public async Task AnalyzerExecutor_NonCooperativeAnalyzer_StopsAtTimeoutBoundary()
    {
        var slowAnalyzer = new NonCooperativeSlowAnalyzer(delayMs: 5000, timeoutMs: 100);
        var executor = new AnalyzerExecutor();
        var context = new AnalysisContext(".", ".", AnalysisDepth.Fast);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        var result = await executor.ExecuteAsync(slowAnalyzer, context, CancellationToken.None);

        stopwatch.Stop();
        Assert.Equal(ModuleStatus.TimedOut, result.Module.Status);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task AnalyzerExecutor_ExternalCancellation_PropagatesCancellation()
    {
        var slowAnalyzer = new SlowAnalyzer(delayMs: 5000, timeoutMs: 5000);
        var executor = new AnalyzerExecutor();
        var context = new AnalysisContext(".", ".", AnalysisDepth.Fast);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            executor.ExecuteAsync(slowAnalyzer, context, cancellation.Token));
    }

    [Fact]
    public async Task AnalyzerExecutor_UnexpectedAnalyzerException_DoesNotExposeRawExceptionMessage()
    {
        var analyzer = new ThrowingAnalyzer("token=secret at C:\\Users\\example\\.npmrc");
        var executor = new AnalyzerExecutor();
        var context = new AnalysisContext(".", ".", AnalysisDepth.Fast);

        var result = await executor.ExecuteAsync(analyzer, context, CancellationToken.None);

        Assert.Equal(ModuleStatus.Failed, result.Module.Status);
        Assert.Equal("Analyzer failed unexpectedly.", result.Module.ErrorMessage);
        Assert.Equal("Analyzer failed unexpectedly.", result.Result.ErrorMessage);
        Assert.DoesNotContain("secret", result.Module.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", result.Result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
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
        Assert.Empty(scan.Score.Categories);
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
        Assert.Equal(ScanWarningKind.PartialCoverage, Assert.Single(result.Module.WarningDetails!).Kind);
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

    [Fact]
    public async Task ScanOrchestrator_SkipsAnalyzersAboveAllowedExecutionSafety()
    {
        var unsafeAnalyzer = new FakeAnalyzerWithRule(
            "unsafe-analyzer",
            "TRUST-SAFE001",
            executionSafety: AnalyzerExecutionSafety.ExecutesRepositoryCode);
        var orchestrator = new ScanOrchestrator([unsafeAnalyzer], new AnalyzerExecutor(), new TrustScorer());

        var scan = await orchestrator.RunAsync(".", ".", AnalysisDepth.Fast, TrustProfile.Personal, CancellationToken.None);

        var module = Assert.Single(scan.Modules);
        Assert.Equal(ModuleStatus.Skipped, module.Status);
        Assert.Contains("ExecutesRepositoryCode", module.SkippedReason);
        Assert.Equal(ModuleStatus.CompletedWithWarnings, scan.Status);
        Assert.Equal(FinalDecisionKind.NeedsManualReview, scan.Score.Decision.Kind);
    }

    [Fact]
    public async Task ScanOrchestrator_SkipsDependentsWhenRequiredAnalyzerDoesNotComplete()
    {
        var dependent = new FakeAnalyzerWithRule("dependent", "TRUST-DEP002", ["unsafe-producer"]);
        var producer = new FakeAnalyzerWithRule(
            "unsafe-producer",
            "TRUST-DEP001",
            executionSafety: AnalyzerExecutionSafety.ExecutesRepositoryCode);
        var orchestrator = new ScanOrchestrator([dependent, producer], new AnalyzerExecutor(), new TrustScorer());

        var scan = await orchestrator.RunAsync(".", ".", AnalysisDepth.Fast, TrustProfile.Personal, CancellationToken.None);

        Assert.Collection(
            scan.Modules,
            module => Assert.Equal("unsafe-producer", module.ModuleId),
            module =>
            {
                Assert.Equal("dependent", module.ModuleId);
                Assert.Equal(ModuleStatus.Skipped, module.Status);
                Assert.Contains("unsafe-producer", module.SkippedReason);
            });
    }

    [Fact]
    public async Task ScanOrchestrator_AssignsFindingFingerprintsBeforeScoring()
    {
        using var directory = TemporaryDirectory.Create();
        var analyzer = new FindingAnalyzer();
        var orchestrator = new ScanOrchestrator([analyzer], new AnalyzerExecutor(), new TrustScorer());

        var scan = await orchestrator.RunAsync(
            ".",
            directory.Path,
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            CancellationToken.None);

        var finding = Assert.Single(scan.Findings);
        Assert.False(string.IsNullOrWhiteSpace(finding.Fingerprint));

        var policy = RepoTrustDoctor.Policies.TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);
        var evaluation = new RepoTrustDoctor.Policies.TrustPolicyEvaluator().Evaluate(scan.Findings, policy);
        var violation = Assert.Single(evaluation.Violations);
        Assert.Equal(finding.Fingerprint, violation.FindingFingerprint);
    }

    private sealed class FakeAnalyzerWithRule : IRepositoryAnalyzer
    {
        private readonly string id;
        private readonly string ruleId;
        private readonly IReadOnlyCollection<string> dependsOn;
        private readonly AnalyzerExecutionSafety executionSafety;

        public FakeAnalyzerWithRule(
            string id,
            string ruleId,
            IReadOnlyCollection<string>? dependsOn = null,
            AnalyzerExecutionSafety executionSafety = AnalyzerExecutionSafety.StaticOnly)
        {
            this.id = id;
            this.ruleId = ruleId;
            this.dependsOn = dependsOn ?? [];
            this.executionSafety = executionSafety;
        }

        public string Id => id;
        public string DisplayName => id;
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => dependsOn;
        public AnalyzerExecutionSafety ExecutionSafety => executionSafety;
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

    private sealed class NonCooperativeSlowAnalyzer : IRepositoryAnalyzer
    {
        private readonly int delayMs;
        private readonly int timeoutMs;

        public NonCooperativeSlowAnalyzer(int delayMs, int timeoutMs)
        {
            this.delayMs = delayMs;
            this.timeoutMs = timeoutMs;
        }

        public string Id => "non-cooperative-slow-analyzer";
        public string DisplayName => "Non Cooperative Slow Analyzer";
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromMilliseconds(timeoutMs);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new("TRUST-SLOW002", "Slow rule", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "Slow", "Wait")
        ];

        public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
        {
            await Task.Delay(delayMs, CancellationToken.None);
            return AnalyzerResult.Completed([]);
        }
    }

    private sealed class ThrowingAnalyzer : IRepositoryAnalyzer
    {
        private readonly string message;

        public ThrowingAnalyzer(string message)
        {
            this.message = message;
        }

        public string Id => "throwing-analyzer";
        public string DisplayName => "Throwing Analyzer";
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new("TRUST-THROW001", "Throwing rule", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "Throw", "Review")
        ];

        public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(message);
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

    private sealed class FindingAnalyzer : IRepositoryAnalyzer
    {
        public string Id => "finding-analyzer";
        public string DisplayName => "Finding Analyzer";
        public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;
        public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;
        public IReadOnlyCollection<string> DependsOn => [];
        public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
        public TimeSpan Timeout => TimeSpan.FromSeconds(10);
        public IReadOnlyCollection<RuleMetadata> Rules =>
        [
            new(
                "TRUST-REPO003",
                "Security policy is missing",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.High,
                "Detects a missing security policy.",
                "Add SECURITY.md.")
        ];

        public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken) =>
            Task.FromResult(AnalyzerResult.Completed(
            [
                new Finding(
                    "TRUST-REPO003",
                    "Security policy is missing",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.High,
                    "SECURITY.md is missing.",
                    [new Evidence("file-missing", "SECURITY.md was not found.")],
                    new Recommendation("Add SECURITY.md."))
            ]));
    }
}

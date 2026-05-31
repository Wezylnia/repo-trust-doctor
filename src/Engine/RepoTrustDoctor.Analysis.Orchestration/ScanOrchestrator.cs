using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.Analysis.Orchestration;

public sealed class ScanOrchestrator
{
    public const string ToolVersion = "0.1.0-alpha";

    private readonly IReadOnlyList<IRepositoryAnalyzer> analyzers;
    private readonly AnalyzerExecutor executor;
    private readonly TrustScorer scorer;

    public ScanOrchestrator(
        IEnumerable<IRepositoryAnalyzer> analyzers,
        AnalyzerExecutor executor,
        TrustScorer scorer)
    {
        this.analyzers = analyzers.OrderBy(analyzer => analyzer.Id, StringComparer.OrdinalIgnoreCase).ToArray();
        this.executor = executor;
        this.scorer = scorer;

        ValidateAnalyzers(this.analyzers);
    }

    private static void ValidateAnalyzers(IReadOnlyList<IRepositoryAnalyzer> analyzers)
    {
        var analyzerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers)
        {
            if (string.IsNullOrWhiteSpace(analyzer.Id))
            {
                throw new InvalidOperationException("An analyzer has an empty or null ID.");
            }

            if (!analyzerIds.Add(analyzer.Id))
            {
                throw new InvalidOperationException($"Duplicate analyzer ID: '{analyzer.Id}'.");
            }

            foreach (var rule in analyzer.Rules)
            {
                if (string.IsNullOrWhiteSpace(rule.RuleId))
                {
                    throw new InvalidOperationException($"Analyzer '{analyzer.Id}' has a rule with an empty or null rule ID.");
                }

                if (!ruleIds.Add(rule.RuleId))
                {
                    throw new InvalidOperationException($"Duplicate rule ID: '{rule.RuleId}' found in analyzer '{analyzer.Id}'.");
                }
            }
        }
    }

    public async Task<RepositoryScan> RunAsync(
        string target,
        string repositoryPath,
        AnalysisDepth depth,
        TrustProfile trustProfile,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var context = new AnalysisContext(target, repositoryPath, depth);
        var modules = new List<ScanModule>();
        var findings = new List<Finding>();

        foreach (var analyzer in analyzers.Where(analyzer => analyzer.MinimumDepth <= depth))
        {
            var execution = await executor.ExecuteAsync(analyzer, context, cancellationToken);
            modules.Add(execution.Module);
            findings.AddRange(execution.Result.Findings);
        }

        var completed = DateTimeOffset.UtcNow;
        var score = scorer.Score(findings);
        var status = modules.Any(module => module.Status is ModuleStatus.Failed or ModuleStatus.TimedOut)
            ? ModuleStatus.CompletedWithWarnings
            : ModuleStatus.Completed;

        return new RepositoryScan(
            Guid.NewGuid(),
            target,
            depth,
            trustProfile,
            ToolVersion,
            status,
            started,
            completed,
            modules,
            findings,
            score);
    }
}

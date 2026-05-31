using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.Analysis.Orchestration;

public sealed class ScanOrchestrator
{
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
    }

    public async Task<RepositoryScan> RunAsync(
        string target,
        string repositoryPath,
        AnalysisDepth depth,
        string trustProfile,
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
            status,
            started,
            completed,
            modules,
            findings,
            score);
    }
}

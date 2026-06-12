using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Scoring;
using RepoTrustDoctor.Shared;

namespace RepoTrustDoctor.Analysis.Orchestration;

public sealed class ScanOrchestrator
{
    public const string ToolVersion = ProductInfo.Version;

    private readonly IReadOnlyList<IRepositoryAnalyzer> analyzers;
    private readonly AnalyzerExecutor executor;
    private readonly TrustScorer scorer;

    public ScanOrchestrator(
        IEnumerable<IRepositoryAnalyzer> analyzers,
        AnalyzerExecutor executor,
        TrustScorer scorer)
    {
        var analyzerList = analyzers.ToArray();
        ValidateAnalyzers(analyzerList);

        this.analyzers = OrderAnalyzers(analyzerList);
        this.executor = executor;
        this.scorer = scorer;
    }

    private static IReadOnlyList<IRepositoryAnalyzer> OrderAnalyzers(IReadOnlyList<IRepositoryAnalyzer> analyzers)
    {
        var byId = analyzers.ToDictionary(analyzer => analyzer.Id, StringComparer.OrdinalIgnoreCase);
        var ordered = new List<IRepositoryAnalyzer>();
        var visiting = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers.OrderBy(analyzer => analyzer.Id, StringComparer.OrdinalIgnoreCase))
        {
            Visit(analyzer, byId, ordered, visiting, visited);
        }

        return ordered;
    }

    private static void Visit(
        IRepositoryAnalyzer analyzer,
        IReadOnlyDictionary<string, IRepositoryAnalyzer> byId,
        List<IRepositoryAnalyzer> ordered,
        HashSet<string> visiting,
        HashSet<string> visited)
    {
        if (visited.Contains(analyzer.Id))
        {
            return;
        }

        if (!visiting.Add(analyzer.Id))
        {
            throw new InvalidOperationException($"Analyzer dependency cycle detected at '{analyzer.Id}'.");
        }

        foreach (var dependency in analyzer.DependsOn)
        {
            var dependencyId = ResolveDependencyId(dependency);
            if (byId.TryGetValue(dependencyId, out var dependencyAnalyzer))
            {
                Visit(dependencyAnalyzer, byId, ordered, visiting, visited);
            }
        }

        visiting.Remove(analyzer.Id);
        visited.Add(analyzer.Id);
        ordered.Add(analyzer);
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

        foreach (var analyzer in analyzers)
        {
            foreach (var dependency in analyzer.DependsOn)
            {
                var dependencyId = ResolveDependencyId(dependency);
                if (!analyzerIds.Contains(dependencyId))
                {
                    throw new InvalidOperationException(
                        $"Analyzer '{analyzer.Id}' depends on unknown analyzer or artifact '{dependency}'.");
                }
            }
        }
    }

    private static string ResolveDependencyId(string dependency) => dependency switch
    {
        "dependency.inventory" => "dependency-inventory",
        "dependency.packageMetadata" => "dependency-metadata",
        "code.coverage" => "codebase-01-coverage-import",
        "code.criticality" => "codebase-02-criticality",
        "code.public-api" => "codebase-04-public-api",
        "code.import-graph" => "codebase-05-import-graph",
        "code.framework-routes" => "codebase-06-framework-routes",
        _ => dependency
    };

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
        var evaluatedCategories = modules
            .Where(m => m.Status is ModuleStatus.Completed or ModuleStatus.CompletedWithWarnings)
            .Select(m => m.Category)
            .Distinct()
            .ToArray();
        var score = scorer.Score(findings, trustProfile, evaluatedCategories);
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
            score,
            context.Artifacts);
    }
}

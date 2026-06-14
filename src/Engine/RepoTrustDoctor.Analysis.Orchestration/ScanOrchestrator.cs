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
    private readonly AnalyzerExecutionSafety maximumExecutionSafety;

    public ScanOrchestrator(
        IEnumerable<IRepositoryAnalyzer> analyzers,
        AnalyzerExecutor executor,
        TrustScorer scorer,
        AnalyzerExecutionSafety maximumExecutionSafety = AnalyzerExecutionSafety.NetworkLookup)
    {
        var analyzerList = analyzers.ToArray();
        ValidateAnalyzers(analyzerList);

        this.analyzers = OrderAnalyzers(analyzerList);
        this.executor = executor;
        this.scorer = scorer;
        this.maximumExecutionSafety = maximumExecutionSafety;
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
        var moduleStatuses = new Dictionary<string, ModuleStatus>(StringComparer.OrdinalIgnoreCase);

        using var fileIndex = RepositoryFileSystem.UseFileIndex(repositoryPath);
        foreach (var analyzer in analyzers.Where(analyzer => analyzer.MinimumDepth <= depth))
        {
            if (TryGetBlockedDependency(analyzer, moduleStatuses, out var blockedDependency))
            {
                var skipped = CreateSkippedModule(
                    analyzer,
                    $"Required analyzer '{blockedDependency}' did not complete successfully.");
                modules.Add(skipped);
                moduleStatuses[analyzer.Id] = skipped.Status;
                continue;
            }

            if (analyzer.ExecutionSafety > maximumExecutionSafety)
            {
                var skipped = CreateSkippedModule(
                    analyzer,
                    $"Analyzer requires {analyzer.ExecutionSafety} execution safety but the scan allows {maximumExecutionSafety}.");
                modules.Add(skipped);
                moduleStatuses[analyzer.Id] = skipped.Status;
                continue;
            }

            var execution = await executor.ExecuteAsync(analyzer, context, cancellationToken);
            modules.Add(execution.Module);
            moduleStatuses[analyzer.Id] = execution.Module.Status;
            findings.AddRange(execution.Result.Findings);
        }

        var completed = DateTimeOffset.UtcNow;
        var fingerprintedFindings = FindingIdentity.AddFingerprints(findings);
        var score = scorer.ScoreScan(fingerprintedFindings, trustProfile, modules);
        var status = modules.Any(module => module.Status is
            ModuleStatus.CompletedWithWarnings or
            ModuleStatus.Failed or
            ModuleStatus.TimedOut or
            ModuleStatus.Skipped or
            ModuleStatus.Cancelled)
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
            fingerprintedFindings,
            score,
            context.Artifacts);
    }

    private static bool TryGetBlockedDependency(
        IRepositoryAnalyzer analyzer,
        IReadOnlyDictionary<string, ModuleStatus> moduleStatuses,
        out string? blockedDependency)
    {
        foreach (var dependency in analyzer.DependsOn)
        {
            var dependencyId = ResolveDependencyId(dependency);
            if (moduleStatuses.TryGetValue(dependencyId, out var status) &&
                status is ModuleStatus.Failed or ModuleStatus.TimedOut or ModuleStatus.Skipped or ModuleStatus.Cancelled)
            {
                blockedDependency = dependencyId;
                return true;
            }
        }

        blockedDependency = null;
        return false;
    }

    private static ScanModule CreateSkippedModule(IRepositoryAnalyzer analyzer, string reason)
    {
        var now = DateTimeOffset.UtcNow;
        return new ScanModule(
            analyzer.Id,
            analyzer.DisplayName,
            analyzer.Category,
            ModuleStatus.Skipped,
            now,
            now,
            0,
            SkippedReason: reason);
    }
}

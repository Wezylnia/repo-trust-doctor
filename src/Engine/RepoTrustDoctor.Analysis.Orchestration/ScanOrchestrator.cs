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
    private readonly IReadOnlyDictionary<string, string> artifactProducers;

    public ScanOrchestrator(
        IEnumerable<IRepositoryAnalyzer> analyzers,
        AnalyzerExecutor executor,
        TrustScorer scorer,
        AnalyzerExecutionSafety maximumExecutionSafety = AnalyzerExecutionSafety.NetworkLookup)
    {
        var analyzerList = analyzers.ToArray();
        var byId = BuildAnalyzerIdMap(analyzerList);
        this.artifactProducers = BuildArtifactProducerMap(analyzerList);
        ValidateAnalyzers(analyzerList, byId);

        this.analyzers = OrderAnalyzers(analyzerList, byId, this.artifactProducers);
        this.executor = executor;
        this.scorer = scorer;
        this.maximumExecutionSafety = maximumExecutionSafety;
    }

    private static IReadOnlyDictionary<string, IRepositoryAnalyzer> BuildAnalyzerIdMap(
        IReadOnlyList<IRepositoryAnalyzer> analyzers)
    {
        var map = new Dictionary<string, IRepositoryAnalyzer>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers)
        {
            if (!map.TryAdd(analyzer.Id, analyzer))
            {
                throw new InvalidOperationException($"Duplicate analyzer ID: '{analyzer.Id}'.");
            }
        }

        return map;
    }

    private static IReadOnlyDictionary<string, string> BuildArtifactProducerMap(
        IReadOnlyList<IRepositoryAnalyzer> analyzers)
    {
        var producers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers)
        {
            foreach (var artifactKey in analyzer.ProducesArtifacts)
            {
                if (string.IsNullOrWhiteSpace(artifactKey))
                {
                    throw new InvalidOperationException(
                        $"Analyzer '{analyzer.Id}' declares an empty produced artifact key.");
                }

                if (producers.TryGetValue(artifactKey, out var existingProducer))
                {
                    throw new InvalidOperationException(
                        $"Artifact '{artifactKey}' is produced by more than one analyzer: '{existingProducer}' and '{analyzer.Id}'.");
                }

                producers[artifactKey] = analyzer.Id;
            }
        }

        return producers;
    }

    private static string? ResolveDependency(
        string dependency,
        IReadOnlyDictionary<string, string> artifactProducers)
    {
        if (artifactProducers.TryGetValue(dependency, out var producerId))
        {
            return producerId;
        }

        return dependency;
    }

    private static IReadOnlyList<IRepositoryAnalyzer> OrderAnalyzers(
        IReadOnlyList<IRepositoryAnalyzer> analyzers,
        IReadOnlyDictionary<string, IRepositoryAnalyzer> byId,
        IReadOnlyDictionary<string, string> artifactProducers)
    {
        var ordered = new List<IRepositoryAnalyzer>();
        var visiting = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers.OrderBy(a => a.Id, StringComparer.OrdinalIgnoreCase))
        {
            Visit(analyzer, byId, artifactProducers, ordered, visiting, visited);
        }

        return ordered;
    }

    private static void Visit(
        IRepositoryAnalyzer analyzer,
        IReadOnlyDictionary<string, IRepositoryAnalyzer> byId,
        IReadOnlyDictionary<string, string> artifactProducers,
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
            var resolvedId = ResolveDependency(dependency, artifactProducers);
            if (resolvedId is not null && byId.TryGetValue(resolvedId, out var dependencyAnalyzer))
            {
                Visit(dependencyAnalyzer, byId, artifactProducers, ordered, visiting, visited);
            }
        }

        visiting.Remove(analyzer.Id);
        visited.Add(analyzer.Id);
        ordered.Add(analyzer);
    }

    private void ValidateAnalyzers(
        IReadOnlyList<IRepositoryAnalyzer> analyzers,
        IReadOnlyDictionary<string, IRepositoryAnalyzer> byId)
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
                var resolvedId = ResolveDependency(dependency, artifactProducers);
                if (resolvedId is null || !byId.ContainsKey(resolvedId))
                {
                    throw new InvalidOperationException(
                        $"Analyzer '{analyzer.Id}' depends on unknown analyzer or artifact '{dependency}'.");
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

        // Load and apply suppression configuration
        var suppressionEngine = FindingSuppressionEngine.Load(repositoryPath);
        var suppressedFindings = new List<Finding>();
        foreach (var finding in fingerprintedFindings)
        {
            var suppression = suppressionEngine.FindActiveSuppression(finding);
            suppressedFindings.Add(suppression is not null ? finding with { Suppression = suppression } : finding);
        }

        var score = scorer.ScoreScan(suppressedFindings, trustProfile, modules);
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
            suppressedFindings,
            score,
            context.Artifacts);
    }

    private bool TryGetBlockedDependency(
        IRepositoryAnalyzer analyzer,
        IReadOnlyDictionary<string, ModuleStatus> moduleStatuses,
        out string? blockedDependency)
    {
        foreach (var dependency in analyzer.DependsOn)
        {
            var resolvedId = ResolveDependency(dependency, artifactProducers);
            if (resolvedId is not null &&
                moduleStatuses.TryGetValue(resolvedId, out var status) &&
                status is ModuleStatus.Failed or ModuleStatus.TimedOut or ModuleStatus.Skipped or ModuleStatus.Cancelled)
            {
                blockedDependency = resolvedId;
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

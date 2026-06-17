using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analysis.Abstractions;

public enum AnalyzerExecutionSafety
{
    StaticOnly,
    NetworkLookup,
    ExecutesTrustedTool,
    ExecutesRepositoryCode
}

public sealed record AnalyzerArtifact(string Key, object Value);

public sealed record RuleMetadata(
    string RuleId,
    string Title,
    AnalysisCategory Category,
    Severity DefaultSeverity,
    Confidence DefaultConfidence,
    string Description,
    string Recommendation);

public sealed record AnalyzerResult(
    ModuleStatus Status,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<AnalyzerArtifact>? Artifacts = null,
    IReadOnlyDictionary<string, string>? Metrics = null,
    IReadOnlyList<string>? Warnings = null,
    IReadOnlyList<ScanWarning>? WarningDetails = null,
    string? ErrorMessage = null)
{
    public static AnalyzerResult Completed(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<AnalyzerArtifact>? artifacts = null,
        IReadOnlyDictionary<string, string>? metrics = null,
        IReadOnlyList<string>? warnings = null,
        IReadOnlyList<ScanWarning>? warningDetails = null) =>
        new(
            ModuleStatus.Completed,
            findings,
            artifacts,
            metrics,
            warningDetails is not null && warnings is null
                ? warningDetails.Select(warning => warning.Message).ToArray()
                : warnings,
            warningDetails);
}

public sealed class AnalysisContext
{
    private readonly Dictionary<string, object> artifacts = new(StringComparer.OrdinalIgnoreCase);

    public AnalysisContext(string target, string repositoryPath, AnalysisDepth depth)
    {
        Target = target;
        RepositoryPath = repositoryPath;
        Depth = depth;
    }

    public string Target { get; }

    public string RepositoryPath { get; }

    public AnalysisDepth Depth { get; }

    public IReadOnlyDictionary<string, object> Artifacts => artifacts;

    public void AddArtifact(AnalyzerArtifact artifact) => artifacts[artifact.Key] = artifact.Value;

    public bool TryGetArtifact<T>(string key, out T? value)
    {
        if (artifacts.TryGetValue(key, out var raw) && raw is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }
}

public interface IRepositoryAnalyzer
{
    string Id { get; }

    string DisplayName { get; }

    AnalysisCategory Category { get; }

    AnalysisDepth MinimumDepth { get; }

    IReadOnlyCollection<string> DependsOn { get; }

    AnalyzerExecutionSafety ExecutionSafety { get; }

    IReadOnlyCollection<RuleMetadata> Rules { get; }

    IReadOnlyCollection<string> ProducesArtifacts => [];

    TimeSpan Timeout { get; }

    Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken);
}

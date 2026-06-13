namespace RepoTrustDoctor.Analysis.Abstractions;

public enum CoverageReportFormat
{
    Cobertura,
    Lcov
}

public enum CodeCriticalityReason
{
    Authentication,
    Authorization,
    Payments,
    Database,
    FileSystem,
    Network,
    Cryptography,
    Secrets,
    LargeFile,
    BroadExceptionHandling,
    Deserialization,
    CommandExecution,
    DynamicCodeEvaluation,
    JavaSerializationHook
}

public sealed record CoverageArtifact(
    IReadOnlyList<CoverageReportInfo> Reports,
    IReadOnlyList<CoverageFileInfo> Files,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.coverage";
}

public sealed record CoverageReportInfo(
    string FilePath,
    CoverageReportFormat Format,
    double? LineRate,
    double? BranchRate,
    int? CoveredLines,
    int? TotalLines,
    int? CoveredBranches,
    int? TotalBranches);

public sealed record CoverageFileInfo(
    string FilePath,
    double? LineRate,
    double? BranchRate,
    int? CoveredLines,
    int? TotalLines,
    int? CoveredBranches,
    int? TotalBranches);

public sealed record CodeCriticalityArtifact(
    IReadOnlyList<CodeCriticalityFile> Files,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.criticality";
}

public sealed record CodeCriticalityFile(
    string FilePath,
    int Score,
    int LineCount,
    IReadOnlyList<CodeCriticalityReason> Reasons,
    int? FirstRelevantLine,
    IReadOnlyDictionary<CodeCriticalityReason, int>? RelevantLines = null);

public sealed record CodePublicApiArtifact(
    IReadOnlyList<string> Symbols,
    string? BaselinePath,
    IReadOnlyList<string> AddedSymbols,
    IReadOnlyList<string> RemovedSymbols,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.public-api";
}

public sealed record ImportGraphArtifact(
    IReadOnlyDictionary<string, IReadOnlyList<string>> Edges,
    IReadOnlyList<CentralFileEntry> CentralFiles,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.import-graph";
}

public sealed record CentralFileEntry(
    string FilePath,
    int InDegree,
    IReadOnlyList<string> ImportedBy);

public sealed record FrameworkRouteArtifact(
    IReadOnlyList<RouteEntry> Routes,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.framework-routes";
}

public sealed record RouteEntry(
    string HttpMethod,
    string? PathPattern,
    string Framework,
    string FilePath,
    int? LineNumber,
    bool HasAuthHint);

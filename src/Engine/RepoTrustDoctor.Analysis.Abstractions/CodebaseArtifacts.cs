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
    BroadExceptionHandling
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
    int? FirstRelevantLine);

public sealed record CodePublicApiArtifact(
    IReadOnlyList<string> Symbols,
    string? BaselinePath,
    IReadOnlyList<string> AddedSymbols,
    IReadOnlyList<string> RemovedSymbols,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "code.public-api";
}

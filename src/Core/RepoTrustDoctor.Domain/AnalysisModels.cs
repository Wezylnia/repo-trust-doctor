namespace RepoTrustDoctor.Domain;

public enum AnalysisCategory
{
    RepositoryHealth,
    CiCd,
    Security,
    Containers,
    Dependencies,
    Releases,
    Licenses,
    Codebase,
    Documentation
}

public enum AnalysisDepth
{
    Fast,
    Standard,
    Deep
}

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum Confidence
{
    Low,
    Medium,
    High
}

public enum ModuleStatus
{
    Waiting,
    Running,
    Completed,
    CompletedWithWarnings,
    Skipped,
    Failed,
    TimedOut,
    Cancelled
}

public enum FinalDecisionKind
{
    SafeToTry,
    UseWithCaution,
    AvoidAsProductionDependency,
    NeedsManualReview
}

public sealed record Evidence(
    string Kind,
    string Message,
    string? FilePath = null,
    int? LineNumber = null,
    string? Value = null);

public sealed record Recommendation(string Message);

public sealed record Finding(
    string RuleId,
    string Title,
    AnalysisCategory Category,
    Severity Severity,
    Confidence Confidence,
    string Message,
    IReadOnlyList<Evidence> Evidence,
    Recommendation Recommendation,
    bool IsBlocking = false,
    IReadOnlyList<string>? Tags = null);

public sealed record ScanModule(
    string ModuleId,
    string DisplayName,
    AnalysisCategory Category,
    ModuleStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    int FindingsCount,
    string? ErrorMessage = null,
    string? SkippedReason = null);

public sealed record CategoryScore(AnalysisCategory Category, int Score);

public sealed record TrustScore(
    int Overall,
    IReadOnlyList<CategoryScore> Categories,
    FinalDecision Decision);

public sealed record FinalDecision(
    FinalDecisionKind Kind,
    IReadOnlyList<string> Reasons);

public sealed record RepositoryScan(
    Guid Id,
    string Target,
    AnalysisDepth Depth,
    string TrustProfile,
    ModuleStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    IReadOnlyList<ScanModule> Modules,
    IReadOnlyList<Finding> Findings,
    TrustScore Score);

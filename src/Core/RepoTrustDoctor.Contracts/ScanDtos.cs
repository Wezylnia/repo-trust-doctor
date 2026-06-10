namespace RepoTrustDoctor.Contracts;

using RepoTrustDoctor.Domain;

public sealed record StartScanRequest(string Target, string Depth = "fast", string Format = "console");

public sealed record StartScanResponse(Guid ScanId, string Status);

public enum ScanLifecycleState
{
    Queued,
    PreparingRepository,
    RunningFastModules,
    RunningStaticAnalyzers,
    RunningDependencyAnalyzers,
    RunningSecurityAnalyzers,
    Scoring,
    Reporting,
    Completed,
    Failed,
    Cancelled
}

public sealed record ScanModuleProgressDto(
    string ModuleId,
    string DisplayName,
    AnalysisCategory Category,
    ModuleStatus Status,
    int FindingsCount,
    string? StatusMessage = null);

public sealed record ScanProgressDto(
    Guid ScanId,
    ScanLifecycleState State,
    DateTimeOffset UpdatedAt,
    IReadOnlyList<ScanModuleProgressDto> Modules,
    int CompletedModuleCount,
    int TotalModuleCount,
    string? StatusMessage = null)
{
    public double CompletionRatio => TotalModuleCount == 0
        ? 0
        : Math.Clamp((double)CompletedModuleCount / TotalModuleCount, 0, 1);
}

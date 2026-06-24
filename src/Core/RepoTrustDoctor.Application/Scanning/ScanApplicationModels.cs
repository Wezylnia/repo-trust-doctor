using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Application.Scanning;

public sealed record ScanRequestOptions(
    string Target,
    AnalysisDepth Depth,
    TrustProfile TrustProfile);

public sealed record ScanJob(
    Guid ScanId,
    ScanRequestOptions Options,
    DateTimeOffset CreatedAt);

public sealed record ScanState(
    Guid ScanId,
    ScanRequestOptions Options,
    ScanLifecycleState State,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? CompletedAt = null,
    RepositoryScan? Result = null,
    string? StatusMessage = null,
    CancellationTokenSource? Cancellation = null)
{
    public ScanStatusResponse ToStatusResponse() =>
        new(
            ScanId,
            Options.Target,
            Options.Depth,
            Options.TrustProfile,
            State,
            CreatedAt,
            UpdatedAt,
            CompletedAt,
            StatusMessage,
            Result?.Modules.Count,
            Result?.Findings.Count,
            Result?.Score.Overall,
            Result?.Score.Decision.Kind,
            State == ScanLifecycleState.Completed ? $"/api/scans/{ScanId}/report?format=json" : null,
            State == ScanLifecycleState.Completed ? $"/api/scans/{ScanId}/report?format=markdown" : null,
            State == ScanLifecycleState.Completed ? $"/api/scans/{ScanId}/report?format=sarif" : null);

    public ScanProgressDto ToProgressDto()
    {
        var modules = Result?.Modules
            .Select(module => new ScanModuleProgressDto(
                module.ModuleId,
                module.DisplayName,
                module.Category,
                module.Status,
                module.FindingsCount,
                module.ErrorMessage ?? module.SkippedReason))
            .ToArray() ?? [];

        var completedModules = modules.Count(module => module.Status is
            ModuleStatus.Completed or
            ModuleStatus.CompletedWithWarnings or
            ModuleStatus.Skipped or
            ModuleStatus.Failed or
            ModuleStatus.TimedOut or
            ModuleStatus.Cancelled);

        return new ScanProgressDto(
            ScanId,
            State,
            UpdatedAt,
            modules,
            completedModules,
            modules.Length,
            StatusMessage);
    }
}

public sealed record EnqueueScanResult(Guid ScanId, bool Accepted, string? ErrorMessage);

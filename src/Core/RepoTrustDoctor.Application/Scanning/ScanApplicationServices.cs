using System.Collections.Concurrent;
using System.Threading.Channels;
using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Application.Scanning;

public interface IRepositoryScanRunner
{
    Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken);
}

public interface IScanStore
{
    ScanState CreateQueued(ScanRequestOptions options, CancellationTokenSource cancellation);

    bool TryGet(Guid scanId, out ScanState? state);

    IReadOnlyList<ScanState> List();

    bool TryUpdate(Guid scanId, Func<ScanState, ScanState> update);
}

public interface IScanJobQueue
{
    ValueTask EnqueueAsync(ScanJob job, CancellationToken cancellationToken);

    ValueTask<ScanJob> DequeueAsync(CancellationToken cancellationToken);
}

public sealed class InMemoryScanStore(TimeProvider? timeProvider = null) : IScanStore
{
    private readonly ConcurrentDictionary<Guid, ScanState> scans = new();
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    public ScanState CreateQueued(ScanRequestOptions options, CancellationTokenSource cancellation)
    {
        var now = timeProvider.GetUtcNow();
        var state = new ScanState(Guid.NewGuid(), options, ScanLifecycleState.Queued, now, now, StatusMessage: "Scan queued.", Cancellation: cancellation);
        scans[state.ScanId] = state;
        return state;
    }

    public bool TryGet(Guid scanId, out ScanState? state) => scans.TryGetValue(scanId, out state);

    public IReadOnlyList<ScanState> List() =>
        scans.Values
            .OrderByDescending(scan => scan.CreatedAt)
            .ToArray();

    public bool TryUpdate(Guid scanId, Func<ScanState, ScanState> update)
    {
        while (scans.TryGetValue(scanId, out var existing))
        {
            var updated = update(existing) with { UpdatedAt = timeProvider.GetUtcNow() };
            if (scans.TryUpdate(scanId, updated, existing))
            {
                return true;
            }
        }

        return false;
    }
}

public sealed class InMemoryScanJobQueue : IScanJobQueue
{
    private readonly Channel<ScanJob> channel = Channel.CreateUnbounded<ScanJob>(new UnboundedChannelOptions
    {
        SingleReader = false,
        SingleWriter = false
    });

    public ValueTask EnqueueAsync(ScanJob job, CancellationToken cancellationToken) =>
        channel.Writer.WriteAsync(job, cancellationToken);

    public ValueTask<ScanJob> DequeueAsync(CancellationToken cancellationToken) =>
        channel.Reader.ReadAsync(cancellationToken);
}

public sealed class ScanRequestValidator
{
    private static readonly string[] SupportedDepths = ["fast", "standard", "deep"];

    public bool TryCreateOptions(StartScanRequest request, out ScanRequestOptions options, out string error)
    {
        options = default!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(request.Target))
        {
            error = "Target is required.";
            return false;
        }

        if (request.Target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            request.Target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) ||
                !string.IsNullOrWhiteSpace(uri.UserInfo) ||
                !string.IsNullOrWhiteSpace(uri.Fragment))
            {
                error = "Repository URL must be an absolute HTTP(S) URL without credentials or fragments.";
                return false;
            }
        }

        if (!SupportedDepths.Contains(request.Depth, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Unsupported depth: {request.Depth}. Supported depths: {string.Join(", ", SupportedDepths)}";
            return false;
        }

        if (!TryParseTrustProfile(request.TrustProfile, out var profile))
        {
            error = $"Unsupported profile: {request.TrustProfile}.";
            return false;
        }

        var depth = request.Depth.ToLowerInvariant() switch
        {
            "fast" => AnalysisDepth.Fast,
            "standard" => AnalysisDepth.Standard,
            "deep" => AnalysisDepth.Deep,
            _ => AnalysisDepth.Fast
        };

        options = new ScanRequestOptions(request.Target.Trim(), depth, profile);
        return true;
    }

    private static bool TryParseTrustProfile(string profileValue, out TrustProfile profile)
    {
        if (Enum.TryParse(profileValue, ignoreCase: true, out profile))
        {
            return true;
        }

        return profileValue.ToLowerInvariant() switch
        {
            "production" or "prod" => Assign(TrustProfile.ProductionDependency, out profile),
            "enterprise" => Assign(TrustProfile.EnterpriseDependency, out profile),
            "cicd" or "ci-cd" => Assign(TrustProfile.CiCdTool, out profile),
            "security" or "security-sensitive" => Assign(TrustProfile.SecuritySensitiveDependency, out profile),
            "container" => Assign(TrustProfile.ContainerDependency, out profile),
            _ => false
        };
    }

    private static bool Assign(TrustProfile value, out TrustProfile profile)
    {
        profile = value;
        return true;
    }
}

public sealed class ScanCoordinator(IScanStore store, IScanJobQueue queue, ScanRequestValidator validator)
{
    public async Task<EnqueueScanResult> StartAsync(StartScanRequest request, CancellationToken cancellationToken)
    {
        if (!validator.TryCreateOptions(request, out var options, out var error))
        {
            return new EnqueueScanResult(Guid.Empty, false, error);
        }

        var cancellation = new CancellationTokenSource();
        var state = store.CreateQueued(options, cancellation);
        await queue.EnqueueAsync(new ScanJob(state.ScanId, options, state.CreatedAt), cancellationToken);
        return new EnqueueScanResult(state.ScanId, true, null);
    }

    public bool TryCancel(Guid scanId)
    {
        if (!store.TryGet(scanId, out var state) || state is null)
        {
            return false;
        }

        state.Cancellation?.Cancel();
        return store.TryUpdate(scanId, current => current with
        {
            State = current.State is ScanLifecycleState.Completed or ScanLifecycleState.Failed
                ? current.State
                : ScanLifecycleState.Cancelled,
            CompletedAt = current.CompletedAt ?? DateTimeOffset.UtcNow,
            StatusMessage = "Scan cancellation requested."
        });
    }
}

public sealed class ScanJobProcessor(IScanStore store, IRepositoryScanRunner runner)
{
    public async Task ProcessAsync(ScanJob job, CancellationToken workerCancellationToken)
    {
        if (!store.TryGet(job.ScanId, out var state) || state is null)
        {
            return;
        }

        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(workerCancellationToken, state.Cancellation?.Token ?? CancellationToken.None);

        try
        {
            store.TryUpdate(job.ScanId, current => current with { State = ScanLifecycleState.PreparingRepository, StatusMessage = "Preparing repository." });
            store.TryUpdate(job.ScanId, current => current with { State = MapRunningState(job.Options.Depth), StatusMessage = "Running analyzers." });

            var scan = await runner.RunAsync(job.Options, linkedCancellation.Token);
            store.TryUpdate(job.ScanId, current => current with
            {
                State = ScanLifecycleState.Completed,
                Result = scan,
                CompletedAt = scan.CompletedAt,
                StatusMessage = "Scan completed."
            });
        }
        catch (OperationCanceledException)
        {
            store.TryUpdate(job.ScanId, current => current with
            {
                State = ScanLifecycleState.Cancelled,
                CompletedAt = DateTimeOffset.UtcNow,
                StatusMessage = "Scan cancelled."
            });
        }
        catch (Exception ex)
        {
            store.TryUpdate(job.ScanId, current => current with
            {
                State = ScanLifecycleState.Failed,
                CompletedAt = DateTimeOffset.UtcNow,
                StatusMessage = $"Scan failed: {ex.Message}"
            });
        }
    }

    private static ScanLifecycleState MapRunningState(AnalysisDepth depth) => depth switch
    {
        AnalysisDepth.Fast => ScanLifecycleState.RunningFastModules,
        AnalysisDepth.Standard => ScanLifecycleState.RunningDependencyAnalyzers,
        AnalysisDepth.Deep => ScanLifecycleState.RunningSecurityAnalyzers,
        _ => ScanLifecycleState.RunningStaticAnalyzers
    };
}

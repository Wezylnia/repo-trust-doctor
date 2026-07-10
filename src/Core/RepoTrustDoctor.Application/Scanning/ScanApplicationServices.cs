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

public sealed class InMemoryScanStore : IScanStore
{
    private const int MaximumTerminalScans = 1_000;
    private static readonly TimeSpan TerminalScanRetention = TimeSpan.FromHours(24);
    private readonly ConcurrentDictionary<Guid, ScanState> scans = new();
    private readonly TimeProvider timeProvider;

    public InMemoryScanStore(TimeProvider? timeProvider = null)
    {
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ScanState CreateQueued(ScanRequestOptions options, CancellationTokenSource cancellation)
    {
        PruneTerminalScans();
        var now = timeProvider.GetUtcNow();
        var state = new ScanState(Guid.NewGuid(), options, ScanLifecycleState.Queued, now, now, StatusMessage: "Scan queued.", Cancellation: cancellation);
        scans[state.ScanId] = state;
        return state;
    }

    public bool TryGet(Guid scanId, out ScanState? state)
    {
        PruneTerminalScans();
        return scans.TryGetValue(scanId, out state);
    }

    public IReadOnlyList<ScanState> List()
    {
        PruneTerminalScans();
        return scans.Values
            .OrderByDescending(scan => scan.CreatedAt)
            .ToArray();
    }

    public bool TryUpdate(Guid scanId, Func<ScanState, ScanState> update)
    {
        PruneTerminalScans();
        while (scans.TryGetValue(scanId, out var existing))
        {
            if (IsTerminal(existing.State))
            {
                return true;
            }

            var updated = update(existing) with { UpdatedAt = timeProvider.GetUtcNow() };
            CancellationTokenSource? cancellationToDispose = null;
            if (IsTerminal(updated.State))
            {
                cancellationToDispose = existing.Cancellation;
                updated = updated with { Cancellation = null };
            }

            if (scans.TryUpdate(scanId, updated, existing))
            {
                cancellationToDispose?.Dispose();
                if (IsTerminal(updated.State))
                {
                    PruneTerminalScans();
                }

                return true;
            }
        }

        return false;
    }

    private static bool IsTerminal(ScanLifecycleState state) =>
        state is ScanLifecycleState.Completed or ScanLifecycleState.Failed or ScanLifecycleState.Cancelled;

    private void PruneTerminalScans()
    {
        var now = timeProvider.GetUtcNow();
        foreach (var scan in scans.Values)
        {
            if (IsTerminal(scan.State) &&
                now - scan.UpdatedAt >= TerminalScanRetention)
            {
                scans.TryRemove(scan.ScanId, out _);
            }
        }

        var overflow = scans.Values
            .Where(scan => IsTerminal(scan.State))
            .OrderByDescending(scan => scan.UpdatedAt)
            .ThenBy(scan => scan.ScanId)
            .Skip(MaximumTerminalScans)
            .Select(scan => scan.ScanId)
            .ToArray();
        foreach (var scanId in overflow)
        {
            scans.TryRemove(scanId, out _);
        }
    }
}

public sealed class InMemoryScanJobQueue : IScanJobQueue
{
    private readonly Channel<ScanJob> channel = Channel.CreateBounded<ScanJob>(new BoundedChannelOptions(100)
    {
        SingleReader = false,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.Wait
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

        if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrWhiteSpace(uri.UserInfo) ||
            !string.IsNullOrWhiteSpace(uri.Fragment) ||
            !string.IsNullOrWhiteSpace(uri.Query))
        {
            error = "API scans require an absolute https://github.com/owner/repo URL without credentials, query strings, or fragments.";
            return false;
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
            profile = TrustProfileCatalog.Normalize(profile);
            return true;
        }

        return profileValue.ToLowerInvariant() switch
        {
            "personal" => Assign(TrustProfile.Personal, out profile),
            "production" or "prod" => Assign(TrustProfile.ProductionDependency, out profile),
            "enterprise" or "enterprise-dependency" => Assign(TrustProfile.SecuritySensitiveDependency, out profile),
            "cicd" or "ci-cd" or "ci" => Assign(TrustProfile.ProductionDependency, out profile),
            "security" or "security-sensitive" => Assign(TrustProfile.SecuritySensitiveDependency, out profile),
            "container" or "docker" => Assign(TrustProfile.ProductionDependency, out profile),
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
        try
        {
            await queue.EnqueueAsync(new ScanJob(state.ScanId, options, state.CreatedAt), cancellationToken);
        }
        catch
        {
            if (!store.TryUpdate(state.ScanId, current => current with
            {
                State = ScanLifecycleState.Failed,
                CompletedAt = DateTimeOffset.UtcNow,
                StatusMessage = "Scan could not be queued."
            }))
            {
                cancellation.Dispose();
            }

            throw;
        }

        return new EnqueueScanResult(state.ScanId, true, null);
    }

    public bool TryCancel(Guid scanId)
    {
        if (!store.TryGet(scanId, out var state) || state is null)
        {
            return false;
        }

        if (state.State is ScanLifecycleState.Completed or ScanLifecycleState.Failed or ScanLifecycleState.Cancelled)
        {
            return true;
        }

        state.Cancellation?.Cancel();
        return store.TryUpdate(scanId, current => current with
        {
            State = ScanLifecycleState.Cancelled,
            CompletedAt = current.CompletedAt ?? DateTimeOffset.UtcNow,
            StatusMessage = "Scan cancellation requested."
        });
    }
}

public sealed class ScanJobProcessor(IScanStore store, IRepositoryScanRunner runner)
{
    internal const string UnexpectedFailureMessage = "Scan failed unexpectedly.";

    public async Task ProcessAsync(ScanJob job, CancellationToken workerCancellationToken)
    {
        if (!store.TryGet(job.ScanId, out var state) || state is null)
        {
            return;
        }

        if (state.State is ScanLifecycleState.Completed or ScanLifecycleState.Failed or ScanLifecycleState.Cancelled)
        {
            return;
        }

        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(workerCancellationToken, state.Cancellation?.Token ?? CancellationToken.None);

        try
        {
            store.TryUpdate(job.ScanId, current => current with { State = ScanLifecycleState.PreparingRepository, StatusMessage = "Preparing repository." });
            store.TryUpdate(job.ScanId, current => current with { State = MapRunningState(job.Options.Depth), StatusMessage = "Running analyzers." });

            var executionOptions = job.Options with
            {
                Progress = progress => store.TryUpdate(job.ScanId, current => current with
                {
                    State = progress.State,
                    StatusMessage = progress.StatusMessage,
                    ProgressModules = progress.Modules ?? current.ProgressModules,
                    ProgressTotalModuleCount = Math.Max(progress.TotalModuleCount, current.ProgressTotalModuleCount)
                })
            };
            var scan = await runner.RunAsync(executionOptions, linkedCancellation.Token);
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
        catch (Exception)
        {
            store.TryUpdate(job.ScanId, current => current with
            {
                State = ScanLifecycleState.Failed,
                CompletedAt = DateTimeOffset.UtcNow,
                StatusMessage = UnexpectedFailureMessage
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

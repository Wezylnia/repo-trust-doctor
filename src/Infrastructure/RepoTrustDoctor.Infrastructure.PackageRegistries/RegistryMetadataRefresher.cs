using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public sealed record RegistryRefreshResult(
    int CandidateCount,
    int RefreshedCount,
    int FailedCount);

public sealed class RegistryMetadataRefresher(
    SqlitePackageMetadataCache cache,
    IReadOnlyCollection<IPackageMetadataClient> clients,
    TimeSpan cacheTtl,
    int refreshBatchSize,
    int maxConcurrency,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<RegistryRefreshResult> RefreshExpiredAsync(
        CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var keys = await cache.GetExpiredKeysAsync(
            now,
            Math.Max(1, refreshBatchSize),
            cancellationToken);
        var clientsByEcosystem = clients.ToDictionary(client => client.Ecosystem);
        var refreshed = 0;
        var failed = 0;
        using var throttle = new SemaphoreSlim(Math.Max(1, maxConcurrency));
        var tasks = keys.Select(async key =>
        {
            if (!clientsByEcosystem.TryGetValue(key.Ecosystem, out var client))
            {
                Interlocked.Increment(ref failed);
                return;
            }

            await throttle.WaitAsync(cancellationToken);
            try
            {
                var package = CreatePackage(key);
                var metadata = await client.GetMetadataAsync(package, cancellationToken);
                await cache.SetAsync(
                    package,
                    metadata,
                    now,
                    now.Add(cacheTtl),
                    cancellationToken);
                Interlocked.Increment(ref refreshed);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref failed);
            }
            finally
            {
                throttle.Release();
            }
        });
        await Task.WhenAll(tasks);
        return new RegistryRefreshResult(keys.Count, refreshed, failed);
    }

    private static DependencyPackageInfo CreatePackage(PackageMetadataCacheKey key) =>
        new(
            key.Ecosystem,
            key.PackageName,
            key.RequestedVersion,
            DependencyScope.Production,
            "local-cache",
            null,
            true,
            true,
            false);
}

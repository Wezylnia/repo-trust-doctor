using System.Collections.Concurrent;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public sealed class CachingPackageMetadataClient : IPackageMetadataClient
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> keyLocks =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly IPackageMetadataClient inner;
    private readonly SqlitePackageMetadataCache cache;
    private readonly TimeSpan cacheTtl;
    private readonly TimeProvider timeProvider;

    public CachingPackageMetadataClient(
        IPackageMetadataClient inner,
        SqlitePackageMetadataCache cache,
        TimeSpan cacheTtl,
        TimeProvider? timeProvider = null)
    {
        this.inner = inner;
        this.cache = cache;
        this.cacheTtl = cacheTtl;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public DependencyEcosystem Ecosystem => inner.Ecosystem;

    public async Task<PackageRegistryMetadata?> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var cached = await cache.GetAsync(package, cancellationToken);
        if (cached?.IsFresh(now) == true)
        {
            return AddCacheMetadata(cached.Metadata, "sqlite", cached.FetchedAt);
        }

        var key = $"{package.Ecosystem}:{package.Name}:{package.Version}";
        var keyLock = keyLocks.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
        await keyLock.WaitAsync(cancellationToken);
        try
        {
            now = timeProvider.GetUtcNow();
            cached = await cache.GetAsync(package, cancellationToken);
            if (cached?.IsFresh(now) == true)
            {
                return AddCacheMetadata(cached.Metadata, "sqlite", cached.FetchedAt);
            }

            var fresh = await inner.GetMetadataAsync(package, cancellationToken);
            if (fresh is not null)
            {
                await cache.SetAsync(
                    package,
                    fresh,
                    now,
                    now.Add(cacheTtl),
                    cancellationToken);
                return AddCacheMetadata(fresh, "network", now);
            }

            if (cached is not null)
            {
                return AddCacheMetadata(cached.Metadata, "sqlite-stale", cached.FetchedAt);
            }

            await cache.SetAsync(
                package,
                null,
                now,
                now.Add(cacheTtl),
                cancellationToken);
            return null;
        }
        finally
        {
            keyLock.Release();
        }
    }

    private static PackageRegistryMetadata? AddCacheMetadata(
        PackageRegistryMetadata? metadata,
        string source,
        DateTimeOffset fetchedAt)
    {
        if (metadata is null)
        {
            return null;
        }

        var values = new Dictionary<string, string>(
            metadata.Metadata ?? new Dictionary<string, string>(),
            StringComparer.OrdinalIgnoreCase)
        {
            ["lookup.source"] = source,
            ["lookup.fetchedAt"] = fetchedAt.ToString("O")
        };
        return metadata with { Metadata = values };
    }
}

using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Data.Sqlite;
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
        var cached = await TryGetCachedAsync(package, cancellationToken);
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
            cached = await TryGetCachedAsync(package, cancellationToken);
            if (cached?.IsFresh(now) == true)
            {
                return AddCacheMetadata(cached.Metadata, "sqlite", cached.FetchedAt);
            }

            PackageRegistryMetadata? fresh;
            try
            {
                fresh = await inner.GetMetadataAsync(package, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch when (cached is not null)
            {
                return AddCacheMetadata(cached.Metadata, "sqlite-stale", cached.FetchedAt);
            }

            if (fresh is not null)
            {
                await TrySetCachedAsync(
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

            await TrySetCachedAsync(
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

    private async Task<PackageMetadataCacheEntry?> TryGetCachedAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        try
        {
            return await cache.GetAsync(package, cancellationToken);
        }
        catch (Exception ex) when (IsCacheFailure(ex))
        {
            return null;
        }
    }

    private async Task TrySetCachedAsync(
        DependencyPackageInfo package,
        PackageRegistryMetadata? metadata,
        DateTimeOffset fetchedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        try
        {
            await cache.SetAsync(
                package,
                metadata,
                fetchedAt,
                expiresAt,
                cancellationToken);
        }
        catch (Exception ex) when (IsCacheFailure(ex))
        {
            // A local cache failure must not discard successful registry metadata.
        }
    }

    private static bool IsCacheFailure(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException or
            JsonException or FormatException;

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

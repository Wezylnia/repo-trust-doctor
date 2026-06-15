using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.LocalData;

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

    public async Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var cached = await TryGetCachedAsync(package, cancellationToken);
        if (cached?.IsFresh(now) == true)
        {
            return CreateCachedResult(cached, "sqlite", isStale: false);
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
                return CreateCachedResult(cached, "sqlite", isStale: false);
            }

            PackageMetadataLookupResult fresh;
            try
            {
                fresh = await inner.GetMetadataAsync(package, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                fresh = PackageMetadataLookupResult.Failure(
                    PackageMetadataLookupStatus.TransientFailure,
                    SafeLookupErrorKind.TransportError,
                    ex.Message);
            }

            if (fresh.Status is PackageMetadataLookupStatus.Found or PackageMetadataLookupStatus.NotFound)
            {
                await TrySetCachedAsync(
                    package,
                    fresh,
                    now,
                    now.Add(cacheTtl),
                    cancellationToken);
                return AddSourceMetadata(fresh, "network", now, isStale: false);
            }

            if (cached is { Status: PackageMetadataLookupStatus.Found, Metadata: not null })
            {
                return AddSourceMetadata(
                    fresh with
                    {
                        Status = PackageMetadataLookupStatus.Found,
                        Metadata = cached.Metadata
                    },
                    "sqlite-stale",
                    cached.FetchedAt,
                    isStale: true);
            }

            return AddSourceMetadata(fresh, "network", now, isStale: false);
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
        PackageMetadataLookupResult result,
        DateTimeOffset fetchedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        try
        {
            await cache.SetAsync(
                package,
                result,
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
            JsonException or FormatException or LocalIntelligenceSchemaException;

    private static PackageMetadataLookupResult CreateCachedResult(
        PackageMetadataCacheEntry cached,
        string source,
        bool isStale) =>
        AddSourceMetadata(
            new PackageMetadataLookupResult(cached.Status, cached.Metadata),
            source,
            cached.FetchedAt,
            isStale);

    private static PackageMetadataLookupResult AddSourceMetadata(
        PackageMetadataLookupResult result,
        string source,
        DateTimeOffset fetchedAt,
        bool isStale)
    {
        if (result.Metadata is null)
        {
            return result with
            {
                Source = source,
                FetchedAt = fetchedAt,
                IsStale = isStale
            };
        }

        var values = new Dictionary<string, string>(
            result.Metadata.Metadata ?? new Dictionary<string, string>(),
            StringComparer.OrdinalIgnoreCase)
        {
            ["lookup.source"] = source,
            ["lookup.fetchedAt"] = fetchedAt.ToString("O")
        };
        return result with
        {
            Metadata = result.Metadata with { Metadata = values },
            Source = source,
            FetchedAt = fetchedAt,
            IsStale = isStale
        };
    }
}

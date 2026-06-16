using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.UnitTests;

public sealed class PackageMetadataCacheTests
{
    [Fact]
    public async Task GetMetadataAsync_ReusesFreshSqliteEntry()
    {
        using var fixture = TemporaryDirectory.Create();
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 6, 14, 10, 0, 0, TimeSpan.Zero));
        var inner = new StubMetadataClient();
        var client = CreateClient(fixture.Path, inner, time);
        var package = CreatePackage("left-pad", "1.0.0");

        var first = await client.GetMetadataAsync(package, CancellationToken.None);
        var second = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal(PackageMetadataLookupStatus.Found, first.Status);
        Assert.Equal("network", first.Metadata!.Metadata?["lookup.source"]);
        Assert.Equal("sqlite", second.Metadata!.Metadata?["lookup.source"]);
    }

    [Fact]
    public async Task GetMetadataAsync_RefreshesExpiredEntry()
    {
        using var fixture = TemporaryDirectory.Create();
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 6, 14, 10, 0, 0, TimeSpan.Zero));
        var inner = new StubMetadataClient();
        var client = CreateClient(fixture.Path, inner, time);
        var package = CreatePackage("left-pad", "1.0.0");

        await client.GetMetadataAsync(package, CancellationToken.None);
        time.Advance(TimeSpan.FromHours(25));
        var refreshed = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.Equal(2, inner.RequestCount);
        Assert.Equal("network", refreshed.Metadata!.Metadata?["lookup.source"]);
    }

    [Fact]
    public async Task GetMetadataAsync_ReturnsStaleEntryWhenRefreshFails()
    {
        using var fixture = TemporaryDirectory.Create();
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 6, 14, 10, 0, 0, TimeSpan.Zero));
        var inner = new StubMetadataClient();
        var client = CreateClient(fixture.Path, inner, time);
        var package = CreatePackage("left-pad", "1.0.0");

        await client.GetMetadataAsync(package, CancellationToken.None);
        time.Advance(TimeSpan.FromHours(25));
        inner.ReturnTransientFailure = true;
        var stale = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.Equal(PackageMetadataLookupStatus.Found, stale.Status);
        Assert.Equal(2, inner.RequestCount);
        Assert.True(stale.IsStale);
        Assert.Equal("sqlite-stale", stale.Metadata!.Metadata?["lookup.source"]);
    }

    [Fact]
    public async Task GetMetadataAsync_SeparatesRequestedVersions()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient();
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));

        await client.GetMetadataAsync(CreatePackage("left-pad", "1.0.0"), CancellationToken.None);
        await client.GetMetadataAsync(CreatePackage("left-pad", "2.0.0"), CancellationToken.None);

        Assert.Equal(2, inner.RequestCount);
    }

    [Fact]
    public async Task GetMetadataAsync_CoalescesConcurrentRequestsAndCleansKeyLock()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient { Delay = TimeSpan.FromMilliseconds(50) };
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));
        var package = CreatePackage("left-pad", "1.0.0");

        await Task.WhenAll(Enumerable
            .Range(0, 20)
            .Select(_ => client.GetMetadataAsync(package, CancellationToken.None)));

        Assert.Equal(1, inner.RequestCount);
        Assert.Equal(0, client.ActiveKeyLockCount);
    }

    [Fact]
    public async Task GetMetadataAsync_DoesNotRetainKeyLocksForDistinctPackages()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient();
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));

        for (var index = 0; index < 200; index++)
        {
            await client.GetMetadataAsync(
                CreatePackage($"package-{index}", "1.0.0"),
                CancellationToken.None);
        }

        Assert.Equal(200, inner.RequestCount);
        Assert.Equal(0, client.ActiveKeyLockCount);
    }

    [Fact]
    public async Task GetMetadataAsync_UsesCaseSensitiveLockKeysForMavenPackages()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient();
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));

        await client.GetMetadataAsync(
            CreatePackage("Com.Example:Library", "1.0.0", DependencyEcosystem.Maven),
            CancellationToken.None);
        await client.GetMetadataAsync(
            CreatePackage("com.example:library", "1.0.0", DependencyEcosystem.Maven),
            CancellationToken.None);

        Assert.Equal(2, inner.RequestCount);
        Assert.Equal(0, client.ActiveKeyLockCount);
    }

    [Fact]
    public async Task GetExpiredKeysAsync_PreservesOriginalPackageName()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        var package = CreatePackage("Example.MixedCase", "1.0.0");
        var now = DateTimeOffset.UtcNow;

        await cache.SetAsync(
            package,
            PackageMetadataLookupResult.NotFound(),
            now.AddDays(-2),
            now.AddDays(-1),
            CancellationToken.None);
        var keys = await cache.GetExpiredKeysAsync(now, 10, CancellationToken.None);

        Assert.Equal("Example.MixedCase", Assert.Single(keys).PackageName);
    }

    [Fact]
    public async Task RefreshExpiredAsync_UsesOriginalPackageName()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        var now = new DateTimeOffset(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);
        var package = CreatePackage("Example.MixedCase", "1.0.0");
        await cache.SetAsync(
            package,
            PackageMetadataLookupResult.NotFound(),
            now.AddDays(-2),
            now.AddDays(-1),
            TestContext.Current.CancellationToken);
        var client = new StubMetadataClient();
        var refresher = new RegistryMetadataRefresher(
            cache,
            [client],
            TimeSpan.FromHours(24),
            100,
            4,
            new FixedTimeProvider(now));

        var result = await refresher.RefreshExpiredAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal(1, result.RefreshedCount);
        Assert.Equal("Example.MixedCase", client.LastPackageName);
    }

    [Fact]
    public async Task GetMetadataAsync_UsesNetworkWhenCacheDatabaseIsCorrupt()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await File.WriteAllTextAsync(
            options.DatabasePath,
            "not a sqlite database",
            TestContext.Current.CancellationToken);
        var inner = new StubMetadataClient();
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        var client = new CachingPackageMetadataClient(
            inner,
            cache,
            options.RegistryCacheTtl);

        var result = await client.GetMetadataAsync(
            CreatePackage("left-pad", "1.0.0"),
            TestContext.Current.CancellationToken);

        Assert.Equal(PackageMetadataLookupStatus.Found, result.Status);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal("network", result.Metadata!.Metadata?["lookup.source"]);
    }

    [Theory]
    [InlineData("{not-json}", "2026-06-14T10:00:00.0000000+00:00", "2026-06-15T10:00:00.0000000+00:00")]
    [InlineData("null", "not-a-date", "2026-06-15T10:00:00.0000000+00:00")]
    public async Task GetMetadataAsync_UsesNetworkWhenCachedRowIsMalformed(
        string metadataJson,
        string fetchedAt,
        string expiresAt)
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        var database = new LocalIntelligenceDatabase(options);
        await database.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        await using (var connection = await database.OpenConnectionAsync(
                         TestContext.Current.CancellationToken))
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                INSERT INTO registry_metadata(
                    ecosystem,
                    package_name,
                    requested_version,
                    metadata_json,
                    fetched_at_utc,
                    expires_at_utc,
                    original_package_name,
                    lookup_status)
                VALUES(
                    $ecosystem,
                    'left-pad',
                    '1.0.0',
                    $json,
                    $fetched,
                    $expires,
                    'left-pad',
                    'Found');
                """;
            command.Parameters.AddWithValue("$ecosystem", (int)DependencyEcosystem.Npm);
            command.Parameters.AddWithValue("$json", metadataJson);
            command.Parameters.AddWithValue("$fetched", fetchedAt);
            command.Parameters.AddWithValue("$expires", expiresAt);
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var inner = new StubMetadataClient();
        var client = new CachingPackageMetadataClient(
            inner,
            new SqlitePackageMetadataCache(database),
            options.RegistryCacheTtl);

        var result = await client.GetMetadataAsync(
            CreatePackage("left-pad", "1.0.0"),
            TestContext.Current.CancellationToken);

        Assert.Equal(PackageMetadataLookupStatus.Found, result.Status);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal("network", result.Metadata!.Metadata?["lookup.source"]);
    }

    [Fact]
    public async Task GetMetadataAsync_ReturnsStaleEntryWhenRegistryThrows()
    {
        using var fixture = TemporaryDirectory.Create();
        var time = new MutableTimeProvider(
            new DateTimeOffset(2026, 6, 14, 10, 0, 0, TimeSpan.Zero));
        var inner = new StubMetadataClient();
        var client = CreateClient(fixture.Path, inner, time);
        var package = CreatePackage("left-pad", "1.0.0");
        await client.GetMetadataAsync(package, TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromHours(25));
        inner.ThrowOnRequest = true;

        var result = await client.GetMetadataAsync(
            package,
            TestContext.Current.CancellationToken);

        Assert.Equal(PackageMetadataLookupStatus.Found, result.Status);
        Assert.True(result.IsStale);
        Assert.Equal("sqlite-stale", result.Metadata!.Metadata?["lookup.source"]);
    }

    [Fact]
    public async Task GetMetadataAsync_DoesNotNegativeCacheTransientFailure()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient { ReturnTransientFailure = true };
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));
        var package = CreatePackage("left-pad", "1.0.0");

        var failed = await client.GetMetadataAsync(package, CancellationToken.None);
        inner.ReturnTransientFailure = false;
        var recovered = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.Equal(PackageMetadataLookupStatus.TransientFailure, failed.Status);
        Assert.Equal(PackageMetadataLookupStatus.Found, recovered.Status);
        Assert.Equal(2, inner.RequestCount);
    }

    [Fact]
    public async Task GetMetadataAsync_CachesConfirmedNotFoundResult()
    {
        using var fixture = TemporaryDirectory.Create();
        var inner = new StubMetadataClient { ReturnNotFound = true };
        var client = CreateClient(
            fixture.Path,
            inner,
            new MutableTimeProvider(DateTimeOffset.UtcNow));
        var package = CreatePackage("missing-package", "1.0.0");

        var first = await client.GetMetadataAsync(package, CancellationToken.None);
        var second = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.Equal(PackageMetadataLookupStatus.NotFound, first.Status);
        Assert.Equal(PackageMetadataLookupStatus.NotFound, second.Status);
        Assert.Equal("sqlite", second.Source);
        Assert.Equal(1, inner.RequestCount);
    }

    [Fact]
    public async Task GetMetadataAsync_DoesNotHideOutageBehindStaleNegativeEntry()
    {
        using var fixture = TemporaryDirectory.Create();
        var time = new MutableTimeProvider(
            new DateTimeOffset(2026, 6, 14, 10, 0, 0, TimeSpan.Zero));
        var inner = new StubMetadataClient { ReturnNotFound = true };
        var client = CreateClient(fixture.Path, inner, time);
        var package = CreatePackage("missing-package", "1.0.0");
        await client.GetMetadataAsync(package, CancellationToken.None);
        time.Advance(TimeSpan.FromHours(25));
        inner.ReturnNotFound = false;
        inner.ReturnTransientFailure = true;

        var result = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.Equal(PackageMetadataLookupStatus.TransientFailure, result.Status);
        Assert.False(result.IsStale);
        Assert.Equal("network", result.Source);
        Assert.Equal(2, inner.RequestCount);
    }

    private static CachingPackageMetadataClient CreateClient(
        string directory,
        IPackageMetadataClient inner,
        TimeProvider timeProvider)
    {
        var options = CreateOptions(directory);
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        return new CachingPackageMetadataClient(inner, cache, options.RegistryCacheTtl, timeProvider);
    }

    private static LocalIntelligenceOptions CreateOptions(string directory) =>
        new()
        {
            DatabasePath = Path.Combine(directory, "intelligence.db"),
            ConnectionPoolingEnabled = false,
            RegistryCacheTtl = TimeSpan.FromHours(24)
        };

    private static DependencyPackageInfo CreatePackage(
        string name,
        string version,
        DependencyEcosystem ecosystem = DependencyEcosystem.Npm) =>
        new(
            ecosystem,
            name,
            version,
            DependencyScope.Production,
            "package.json",
            "package-lock.json",
            true,
            true,
            false);

    private sealed class StubMetadataClient : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem => DependencyEcosystem.Npm;

        private int requestCount;

        public int RequestCount => requestCount;

        public bool ReturnNotFound { get; set; }

        public bool ReturnTransientFailure { get; set; }

        public bool ThrowOnRequest { get; set; }

        public TimeSpan Delay { get; set; }

        public string? LastPackageName { get; private set; }

        public async Task<PackageMetadataLookupResult> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref requestCount);
            LastPackageName = package.Name;
            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, cancellationToken);
            }

            if (ThrowOnRequest)
            {
                throw new HttpRequestException("simulated registry failure");
            }

            if (ReturnTransientFailure)
            {
                return PackageMetadataLookupResult.Failure(
                    PackageMetadataLookupStatus.TransientFailure,
                    SafeLookupErrorKind.Timeout,
                    "simulated timeout");
            }

            if (ReturnNotFound)
            {
                return PackageMetadataLookupResult.NotFound();
            }

            return PackageMetadataLookupResult.Found(
                new PackageRegistryMetadata(
                    package.Ecosystem,
                    package.Name,
                    package.Version,
                    "3.0.0",
                    DateTimeOffset.UtcNow,
                    false,
                    false,
                    null,
                    null,
                    "MIT",
                    null,
                    "registry.test"));
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now = now.Add(duration);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

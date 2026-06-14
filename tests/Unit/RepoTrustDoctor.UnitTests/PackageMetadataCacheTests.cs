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
        Assert.Equal("network", first!.Metadata?["lookup.source"]);
        Assert.Equal("sqlite", second!.Metadata?["lookup.source"]);
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
        Assert.Equal("network", refreshed?.Metadata?["lookup.source"]);
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
        inner.ReturnNull = true;
        var stale = await client.GetMetadataAsync(package, CancellationToken.None);

        Assert.NotNull(stale);
        Assert.Equal(2, inner.RequestCount);
        Assert.Equal("sqlite-stale", stale!.Metadata?["lookup.source"]);
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
    public async Task GetExpiredKeysAsync_PreservesOriginalPackageName()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        var package = CreatePackage("Example.MixedCase", "1.0.0");
        var now = DateTimeOffset.UtcNow;

        await cache.SetAsync(package, null, now.AddDays(-2), now.AddDays(-1), CancellationToken.None);
        var keys = await cache.GetExpiredKeysAsync(now, 10, CancellationToken.None);

        Assert.Equal("Example.MixedCase", Assert.Single(keys).PackageName);
    }

    [Fact]
    public async Task DatabaseInitialization_MigratesVersionOneRegistryTable()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await using (var connection = new SqliteConnection(
                         $"Data Source={options.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE registry_metadata (
                    ecosystem INTEGER NOT NULL,
                    package_name TEXT NOT NULL,
                    requested_version TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    fetched_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    PRIMARY KEY (ecosystem, package_name, requested_version)
                );
                """;
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var database = new LocalIntelligenceDatabase(options);
        await database.EnsureInitializedAsync(CancellationToken.None);
        var cache = new SqlitePackageMetadataCache(database);

        var keys = await cache.GetExpiredKeysAsync(DateTimeOffset.UtcNow, 10, CancellationToken.None);

        Assert.Empty(keys);
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
            null,
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
    public async Task DatabaseInitialization_IsSafeAcrossConcurrentInstances()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        var databases = Enumerable.Range(0, 24)
            .Select(_ => new LocalIntelligenceDatabase(options))
            .ToArray();

        await Task.WhenAll(databases.Select(database =>
            database.EnsureInitializedAsync(TestContext.Current.CancellationToken)));

        var cache = new SqlitePackageMetadataCache(databases[0]);
        await cache.SetAsync(
            CreatePackage("left-pad", "1.0.0"),
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1),
            TestContext.Current.CancellationToken);
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

        Assert.NotNull(result);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal("network", result!.Metadata?["lookup.source"]);
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

        Assert.NotNull(result);
        Assert.Equal("sqlite-stale", result!.Metadata?["lookup.source"]);
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

    private static DependencyPackageInfo CreatePackage(string name, string version) =>
        new(
            DependencyEcosystem.Npm,
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

        public int RequestCount { get; private set; }

        public bool ReturnNull { get; set; }

        public bool ThrowOnRequest { get; set; }

        public string? LastPackageName { get; private set; }

        public Task<PackageRegistryMetadata?> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            LastPackageName = package.Name;
            if (ThrowOnRequest)
            {
                throw new HttpRequestException("simulated registry failure");
            }

            return Task.FromResult(ReturnNull
                ? null
                : new PackageRegistryMetadata(
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

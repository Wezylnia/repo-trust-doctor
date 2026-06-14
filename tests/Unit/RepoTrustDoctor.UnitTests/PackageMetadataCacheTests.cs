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

    private static CachingPackageMetadataClient CreateClient(
        string directory,
        IPackageMetadataClient inner,
        TimeProvider timeProvider)
    {
        var options = new LocalIntelligenceOptions
        {
            DatabasePath = Path.Combine(directory, "intelligence.db"),
            ConnectionPoolingEnabled = false,
            RegistryCacheTtl = TimeSpan.FromHours(24)
        };
        var cache = new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options));
        return new CachingPackageMetadataClient(inner, cache, options.RegistryCacheTtl, timeProvider);
    }

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

        public Task<PackageRegistryMetadata?> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            RequestCount++;
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
}

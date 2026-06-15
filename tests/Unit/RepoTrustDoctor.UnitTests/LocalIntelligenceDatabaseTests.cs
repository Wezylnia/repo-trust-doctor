using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.UnitTests;

public sealed class LocalIntelligenceDatabaseTests
{
    [Fact]
    public async Task EnsureInitializedAsync_MigratesVersionOneRegistryTable()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await using (var connection = CreateConnection(options.DatabasePath))
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
        await database.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        var cache = new SqlitePackageMetadataCache(database);

        var keys = await cache.GetExpiredKeysAsync(
            DateTimeOffset.UtcNow,
            10,
            TestContext.Current.CancellationToken);

        Assert.Empty(keys);
    }

    [Fact]
    public async Task EnsureInitializedAsync_DoesNotTrustLegacyNullAsNotFound()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await using (var connection = CreateConnection(options.DatabasePath))
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
                    original_package_name TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (ecosystem, package_name, requested_version)
                );

                INSERT INTO registry_metadata(
                    ecosystem,
                    package_name,
                    requested_version,
                    metadata_json,
                    fetched_at_utc,
                    expires_at_utc,
                    original_package_name)
                VALUES(
                    $ecosystem,
                    'missing-package',
                    '1.0.0',
                    'null',
                    '2026-06-14T10:00:00.0000000+00:00',
                    '2026-06-16T10:00:00.0000000+00:00',
                    'missing-package');
                """;
            command.Parameters.AddWithValue("$ecosystem", (int)DependencyEcosystem.Npm);
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var inner = new StubMetadataClient();
        var client = new CachingPackageMetadataClient(
            inner,
            new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options)),
            options.RegistryCacheTtl);

        var result = await client.GetMetadataAsync(
            CreatePackage("missing-package", "1.0.0"),
            TestContext.Current.CancellationToken);

        Assert.Equal(PackageMetadataLookupStatus.Found, result.Status);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal("network", result.Source);
    }

    [Fact]
    public async Task EnsureInitializedAsync_IsSafeAcrossConcurrentInstances()
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
            PackageMetadataLookupResult.NotFound(),
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1),
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task EnsureInitializedAsync_RejectsNewerSchemaWithoutDowngradingMarker()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await CreateSchemaVersionDatabaseAsync(options.DatabasePath, "99");
        var database = new LocalIntelligenceDatabase(options);

        var exception = await Assert.ThrowsAsync<LocalIntelligenceSchemaException>(() =>
            database.EnsureInitializedAsync(TestContext.Current.CancellationToken));

        Assert.Contains("newer", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("99", await ReadSchemaVersionAsync(options.DatabasePath));
    }

    [Theory]
    [InlineData("")]
    [InlineData("-1")]
    [InlineData("not-a-number")]
    public async Task EnsureInitializedAsync_RejectsInvalidSchemaVersion(string version)
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await CreateSchemaVersionDatabaseAsync(options.DatabasePath, version);

        await Assert.ThrowsAsync<LocalIntelligenceSchemaException>(() =>
            new LocalIntelligenceDatabase(options).EnsureInitializedAsync(
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CacheClient_UsesNetworkWhenDatabaseSchemaIsNewer()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await CreateSchemaVersionDatabaseAsync(options.DatabasePath, "99");
        var inner = new StubMetadataClient();
        var client = new CachingPackageMetadataClient(
            inner,
            new SqlitePackageMetadataCache(new LocalIntelligenceDatabase(options)),
            options.RegistryCacheTtl);

        var result = await client.GetMetadataAsync(
            CreatePackage("left-pad", "1.0.0"),
            TestContext.Current.CancellationToken);

        Assert.Equal(PackageMetadataLookupStatus.Found, result.Status);
        Assert.Equal("network", result.Source);
        Assert.Equal(1, inner.RequestCount);
        Assert.Equal("99", await ReadSchemaVersionAsync(options.DatabasePath));
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

    private static SqliteConnection CreateConnection(string databasePath) =>
        new($"Data Source={databasePath};Pooling=False");

    private static async Task CreateSchemaVersionDatabaseAsync(
        string databasePath,
        string version)
    {
        await using var connection = CreateConnection(databasePath);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE local_schema (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT INTO local_schema(key, value)
            VALUES ('schema_version', $version);
            """;
        command.Parameters.AddWithValue("$version", version);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<string?> ReadSchemaVersionAsync(string databasePath)
    {
        await using var connection = new SqliteConnection(
            $"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT value
            FROM local_schema
            WHERE key = 'schema_version';
            """;
        return await command.ExecuteScalarAsync(TestContext.Current.CancellationToken) as string;
    }

    private sealed class StubMetadataClient : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem => DependencyEcosystem.Npm;

        public int RequestCount { get; private set; }

        public Task<PackageMetadataLookupResult> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(PackageMetadataLookupResult.Found(
                new PackageRegistryMetadata(
                    package.Ecosystem,
                    package.Name,
                    package.Version,
                    package.Version,
                    DateTimeOffset.UtcNow,
                    false,
                    false,
                    null,
                    null,
                    "MIT",
                    null,
                    "registry.test")));
        }
    }
}

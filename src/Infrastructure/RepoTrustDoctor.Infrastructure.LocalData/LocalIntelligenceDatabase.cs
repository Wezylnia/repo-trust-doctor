using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;

namespace RepoTrustDoctor.Infrastructure.LocalData;

public sealed class LocalIntelligenceDatabase
{
    private const int SchemaVersion = 2;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> InitializationLocks =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly string connectionString;
    private volatile bool initialized;

    public LocalIntelligenceDatabase(LocalIntelligenceOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath);
        DatabasePath = Path.GetFullPath(options.DatabasePath);
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = options.ConnectionPoolingEnabled,
            DefaultTimeout = 30
        };
        connectionString = builder.ToString();
    }

    public string DatabasePath { get; }

    public async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        return await OpenUninitializedConnectionAsync(cancellationToken);
    }

    public async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (initialized)
        {
            return;
        }

        var initializationLock = InitializationLocks.GetOrAdd(
            DatabasePath,
            static _ => new SemaphoreSlim(1, 1));
        await initializationLock.WaitAsync(cancellationToken);
        try
        {
            if (initialized)
            {
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
            await using var connection = await OpenUninitializedConnectionAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = SchemaSql;
            await command.ExecuteNonQueryAsync(cancellationToken);
            await EnsureRegistryOriginalPackageNameColumnAsync(
                connection,
                transaction,
                cancellationToken);

            await using var versionCommand = connection.CreateCommand();
            versionCommand.Transaction = transaction;
            versionCommand.CommandText = """
                INSERT INTO local_schema(key, value)
                VALUES ('schema_version', $version)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """;
            versionCommand.Parameters.AddWithValue("$version", SchemaVersion.ToString());
            await versionCommand.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            initialized = true;
        }
        finally
        {
            initializationLock.Release();
        }
    }

    private async Task<SqliteConnection> OpenUninitializedConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;
                PRAGMA busy_timeout = 30000;
                """;
            await command.ExecuteNonQueryAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private static async Task EnsureRegistryOriginalPackageNameColumnAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var columnsCommand = connection.CreateCommand();
        columnsCommand.Transaction = transaction;
        columnsCommand.CommandText = "PRAGMA table_info(registry_metadata);";
        await using var reader = await columnsCommand.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (string.Equals(
                    reader.GetString(1),
                    "original_package_name",
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        await reader.DisposeAsync();
        await using var migrationCommand = connection.CreateCommand();
        migrationCommand.Transaction = transaction;
        migrationCommand.CommandText = """
            ALTER TABLE registry_metadata
            ADD COLUMN original_package_name TEXT NOT NULL DEFAULT '';
            """;
        await migrationCommand.ExecuteNonQueryAsync(cancellationToken);
    }

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS local_schema (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS registry_metadata (
            ecosystem INTEGER NOT NULL,
            package_name TEXT NOT NULL,
            requested_version TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            fetched_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            original_package_name TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (ecosystem, package_name, requested_version)
        );

        CREATE INDEX IF NOT EXISTS ix_registry_metadata_expiry
            ON registry_metadata(expires_at_utc);

        CREATE TABLE IF NOT EXISTS osv_advisories (
            advisory_id TEXT PRIMARY KEY,
            modified_at_utc TEXT NULL,
            withdrawn_at_utc TEXT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS osv_packages (
            advisory_id TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            PRIMARY KEY (advisory_id, ecosystem, package_name),
            FOREIGN KEY (advisory_id)
                REFERENCES osv_advisories(advisory_id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS ix_osv_packages_lookup
            ON osv_packages(ecosystem, package_name);

        CREATE TABLE IF NOT EXISTS feed_state (
            feed_key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        );
        """;
}

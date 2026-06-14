using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.LocalData;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public sealed record OsvStoredAdvisory(
    string Id,
    string RawJson);

public sealed class SqliteOsvAdvisoryStore(LocalIntelligenceDatabase database)
{
    public async Task<bool> IsEcosystemReadyAsync(
        string ecosystem,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM feed_state
            WHERE feed_key = $key
              AND value = 'ready'
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$key", ReadyKey(ecosystem));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    public async Task<IReadOnlyList<OsvStoredAdvisory>> GetCandidatesAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var results = await GetCandidatesAsync([package], cancellationToken);
        return results.Count == 0 ? [] : results[0];
    }

    public async Task<IReadOnlyList<IReadOnlyList<OsvStoredAdvisory>>> GetCandidatesAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        if (packages.Count == 0)
        {
            return [];
        }

        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        var results = new List<IReadOnlyList<OsvStoredAdvisory>>(packages.Count);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT advisory.advisory_id, advisory.raw_json
            FROM osv_packages AS package
            INNER JOIN osv_advisories AS advisory
                ON advisory.advisory_id = package.advisory_id
            WHERE package.ecosystem = $ecosystem
              AND package.package_name = $package_name
              AND advisory.withdrawn_at_utc IS NULL
            ORDER BY advisory.advisory_id;
            """;
        command.Parameters.Add("$ecosystem", SqliteType.Text);
        command.Parameters.Add("$package_name", SqliteType.Text);
        command.Prepare();
        foreach (var package in packages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ecosystem = OsvEcosystemNames.GetName(package.Ecosystem);
            if (ecosystem is null)
            {
                results.Add([]);
                continue;
            }

            command.Parameters["$ecosystem"].Value = Normalize(ecosystem);
            command.Parameters["$package_name"].Value = Normalize(package.Name);

            var packageResults = new List<OsvStoredAdvisory>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                packageResults.Add(new OsvStoredAdvisory(reader.GetString(0), reader.GetString(1)));
            }

            results.Add(packageResults);
        }

        return results;
    }

    public async Task<string?> GetStateAsync(
        string key,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM feed_state WHERE feed_key = $key;";
        command.Parameters.AddWithValue("$key", key);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    public async Task SetStateAsync(
        string key,
        string value,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken,
        SqliteConnection? existingConnection = null,
        SqliteTransaction? transaction = null)
    {
        var ownsConnection = existingConnection is null;
        var connection = existingConnection ??
                         await database.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO feed_state(feed_key, value, updated_at_utc)
                VALUES($key, $value, $updated_at)
                ON CONFLICT(feed_key)
                DO UPDATE SET
                    value = excluded.value,
                    updated_at_utc = excluded.updated_at_utc;
                """;
            command.Parameters.AddWithValue("$key", key);
            command.Parameters.AddWithValue("$value", value);
            command.Parameters.AddWithValue("$updated_at", updatedAt.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            if (ownsConnection)
            {
                await connection.DisposeAsync();
            }
        }
    }

    internal async Task<SqliteConnection> OpenConnectionAsync(
        CancellationToken cancellationToken) =>
        await database.OpenConnectionAsync(cancellationToken);

    internal static string ReadyKey(string ecosystem) =>
        $"osv:{Normalize(ecosystem)}:status";

    internal static string LastFullKey(string ecosystem) =>
        $"osv:{Normalize(ecosystem)}:last-full";

    internal static string LastIncrementalKey(string ecosystem) =>
        $"osv:{Normalize(ecosystem)}:last-incremental";

    internal static string Normalize(string value) =>
        value.Trim().ToLowerInvariant();
}

using System.Text.Json;
using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.LocalData;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public sealed record PackageMetadataCacheEntry(
    PackageMetadataLookupStatus Status,
    PackageRegistryMetadata? Metadata,
    DateTimeOffset FetchedAt,
    DateTimeOffset ExpiresAt)
{
    public bool IsFresh(DateTimeOffset now) => ExpiresAt > now;
}

public sealed record PackageMetadataCacheKey(
    DependencyEcosystem Ecosystem,
    string PackageName,
    string RequestedVersion);

public sealed class SqlitePackageMetadataCache(LocalIntelligenceDatabase database)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<PackageMetadataCacheEntry?> GetAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT metadata_json, lookup_status, fetched_at_utc, expires_at_utc
            FROM registry_metadata
            WHERE ecosystem = $ecosystem
              AND package_name = $package_name
              AND requested_version = $requested_version;
            """;
        AddKeyParameters(command, package);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var json = reader.GetString(0);
        if (!Enum.TryParse<PackageMetadataLookupStatus>(
                reader.GetString(1),
                ignoreCase: true,
                out var status) ||
            status is not (PackageMetadataLookupStatus.Found or PackageMetadataLookupStatus.NotFound))
        {
            return null;
        }

        var metadata = JsonSerializer.Deserialize<PackageRegistryMetadata?>(json, JsonOptions);
        if (status == PackageMetadataLookupStatus.Found && metadata is null)
        {
            return null;
        }

        return new PackageMetadataCacheEntry(
            status,
            metadata,
            DateTimeOffset.Parse(reader.GetString(2)),
            DateTimeOffset.Parse(reader.GetString(3)));
    }

    public async Task SetAsync(
        DependencyPackageInfo package,
        PackageMetadataLookupResult result,
        DateTimeOffset fetchedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
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
                $package_name,
                $requested_version,
                $metadata_json,
                $fetched_at_utc,
                $expires_at_utc,
                $original_package_name,
                $lookup_status)
            ON CONFLICT(ecosystem, package_name, requested_version)
            DO UPDATE SET
                metadata_json = excluded.metadata_json,
                fetched_at_utc = excluded.fetched_at_utc,
                expires_at_utc = excluded.expires_at_utc,
                original_package_name = excluded.original_package_name,
                lookup_status = excluded.lookup_status;
            """;
        if (result.Status is not (PackageMetadataLookupStatus.Found or PackageMetadataLookupStatus.NotFound))
        {
            throw new ArgumentException(
                "Only found and not-found registry results may be cached.",
                nameof(result));
        }

        AddKeyParameters(command, package);
        command.Parameters.AddWithValue(
            "$metadata_json",
            JsonSerializer.Serialize(result.Metadata, JsonOptions));
        command.Parameters.AddWithValue("$fetched_at_utc", fetchedAt.ToString("O"));
        command.Parameters.AddWithValue("$expires_at_utc", expiresAt.ToString("O"));
        command.Parameters.AddWithValue("$original_package_name", package.Name.Trim());
        command.Parameters.AddWithValue("$lookup_status", result.Status.ToString());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<PackageMetadataCacheKey>> GetExpiredKeysAsync(
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                ecosystem,
                COALESCE(NULLIF(original_package_name, ''), package_name),
                requested_version
            FROM registry_metadata
            WHERE expires_at_utc <= $now
            ORDER BY expires_at_utc
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$now", now.ToString("O"));
        command.Parameters.AddWithValue("$limit", limit);

        var results = new List<PackageMetadataCacheKey>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new PackageMetadataCacheKey(
                (DependencyEcosystem)reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2)));
        }

        return results;
    }

    private static void AddKeyParameters(
        SqliteCommand command,
        DependencyPackageInfo package)
    {
        command.Parameters.AddWithValue("$ecosystem", (int)package.Ecosystem);
        command.Parameters.AddWithValue("$package_name", NormalizePackageName(package));
        command.Parameters.AddWithValue(
            "$requested_version",
            package.Version?.Trim() ?? string.Empty);
    }

    private static string NormalizePackageName(DependencyPackageInfo package) =>
        PackageMetadataIdentity.NormalizePackageName(package.Ecosystem, package.Name);
}

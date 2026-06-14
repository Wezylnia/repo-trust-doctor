using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public sealed record OsvImportResult(
    int AdvisoryCount,
    int PackageMappingCount);

public sealed class OsvDumpImporter(SqliteOsvAdvisoryStore store)
{
    private const int MaximumEntries = 500_000;
    private const long MaximumEntryBytes = 16L * 1024 * 1024;
    private const long MaximumExpandedBytes = 8L * 1024 * 1024 * 1024;

    public async Task<OsvImportResult> ImportFullArchiveAsync(
        string ecosystem,
        Stream zipStream,
        DateTimeOffset importedAt,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ecosystem);
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);
        ValidateArchive(archive);

        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await DeleteEcosystemMappingsAsync(connection, transaction, ecosystem, cancellationToken);
        await using var commands = new PreparedImportCommands(connection, transaction);

        var advisoryCount = 0;
        var mappingCount = 0;
        foreach (var entry in archive.Entries.Where(entry =>
                     entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var stream = entry.Open();
            using var document = await JsonDocument.ParseAsync(
                stream,
                new JsonDocumentOptions { MaxDepth = 128 },
                cancellationToken);
            var record = ParseRecord(document.RootElement, ecosystem);
            if (record is null)
            {
                continue;
            }

            await commands.UpsertAsync(record, cancellationToken);
            advisoryCount++;
            mappingCount += record.Packages.Count;
        }

        if (advisoryCount == 0)
        {
            throw new InvalidDataException(
                $"OSV archive for '{ecosystem}' did not contain any valid advisory records.");
        }

        await DeleteOrphanAdvisoriesAsync(connection, transaction, cancellationToken);
        await store.SetStateAsync(
            SqliteOsvAdvisoryStore.ReadyKey(ecosystem),
            "ready",
            importedAt,
            cancellationToken,
            connection,
            transaction);
        await store.SetStateAsync(
            SqliteOsvAdvisoryStore.LastFullKey(ecosystem),
            importedAt.ToString("O"),
            importedAt,
            cancellationToken,
            connection,
            transaction);
        await store.SetStateAsync(
            SqliteOsvAdvisoryStore.LastIncrementalKey(ecosystem),
            importedAt.ToString("O"),
            importedAt,
            cancellationToken,
            connection,
            transaction);
        await transaction.CommitAsync(cancellationToken);
        return new OsvImportResult(advisoryCount, mappingCount);
    }

    public async Task<bool> ImportAdvisoryAsync(
        string ecosystem,
        string json,
        CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 128 });
        var record = ParseRecord(document.RootElement, ecosystem);
        if (record is null)
        {
            return false;
        }

        await using var connection = await store.OpenConnectionAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var commands = new PreparedImportCommands(connection, transaction);
        await DeleteAdvisoryMappingsAsync(
            connection,
            transaction,
            record.Id,
            ecosystem,
            cancellationToken);
        await commands.UpsertAsync(record, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private static OsvImportRecord? ParseRecord(
        JsonElement root,
        string importedEcosystem)
    {
        var id = ReadString(root, "id");
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        var packages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("affected", out var affected) &&
            affected.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in affected.EnumerateArray())
            {
                if (!item.TryGetProperty("package", out var package) ||
                    package.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var ecosystem = ReadString(package, "ecosystem");
                var name = ReadString(package, "name");
                if (string.Equals(ecosystem, importedEcosystem, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(name))
                {
                    packages.Add(OsvPackageIdentity.NormalizeForLookup(
                        importedEcosystem,
                        name));
                }
            }
        }

        if (packages.Count == 0)
        {
            return null;
        }

        return new OsvImportRecord(
            id,
            ReadString(root, "modified"),
            ReadString(root, "withdrawn"),
            root.GetRawText(),
            importedEcosystem,
            packages);
    }

    private static async Task DeleteEcosystemMappingsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string ecosystem,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM osv_packages WHERE ecosystem = $ecosystem;";
        command.Parameters.AddWithValue("$ecosystem", SqliteOsvAdvisoryStore.Normalize(ecosystem));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task DeleteAdvisoryMappingsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string advisoryId,
        string ecosystem,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM osv_packages
            WHERE advisory_id = $id AND ecosystem = $ecosystem;
            """;
        command.Parameters.AddWithValue("$id", advisoryId);
        command.Parameters.AddWithValue("$ecosystem", SqliteOsvAdvisoryStore.Normalize(ecosystem));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task DeleteOrphanAdvisoriesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM osv_advisories
            WHERE NOT EXISTS (
                SELECT 1
                FROM osv_packages
                WHERE osv_packages.advisory_id = osv_advisories.advisory_id
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void ValidateArchive(ZipArchive archive)
    {
        if (archive.Entries.Count > MaximumEntries)
        {
            throw new InvalidDataException(
                $"OSV archive contains more than {MaximumEntries:N0} entries.");
        }

        long expandedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            if (entry.Length > MaximumEntryBytes)
            {
                throw new InvalidDataException(
                    $"OSV archive entry '{entry.FullName}' exceeds {MaximumEntryBytes / (1024 * 1024)} MiB.");
            }

            expandedBytes = checked(expandedBytes + entry.Length);
            if (expandedBytes > MaximumExpandedBytes)
            {
                throw new InvalidDataException("OSV archive expanded size exceeds 8 GiB.");
            }
        }
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private sealed record OsvImportRecord(
        string Id,
        string? ModifiedAt,
        string? WithdrawnAt,
        string RawJson,
        string ImportedEcosystem,
        IReadOnlySet<string> Packages);

    private sealed class PreparedImportCommands : IAsyncDisposable
    {
        private readonly SqliteCommand advisoryCommand;
        private readonly SqliteCommand packageCommand;

        public PreparedImportCommands(
            SqliteConnection connection,
            SqliteTransaction transaction)
        {
            advisoryCommand = connection.CreateCommand();
            advisoryCommand.Transaction = transaction;
            advisoryCommand.CommandText = """
                INSERT INTO osv_advisories(
                    advisory_id,
                    modified_at_utc,
                    withdrawn_at_utc,
                    raw_json)
                VALUES($id, $modified, $withdrawn, $json)
                ON CONFLICT(advisory_id)
                DO UPDATE SET
                    modified_at_utc = excluded.modified_at_utc,
                    withdrawn_at_utc = excluded.withdrawn_at_utc,
                    raw_json = excluded.raw_json;
                """;
            advisoryCommand.Parameters.Add("$id", SqliteType.Text);
            advisoryCommand.Parameters.Add("$modified", SqliteType.Text);
            advisoryCommand.Parameters.Add("$withdrawn", SqliteType.Text);
            advisoryCommand.Parameters.Add("$json", SqliteType.Text);
            advisoryCommand.Prepare();

            packageCommand = connection.CreateCommand();
            packageCommand.Transaction = transaction;
            packageCommand.CommandText = """
                INSERT OR IGNORE INTO osv_packages(advisory_id, ecosystem, package_name)
                VALUES($id, $ecosystem, $package);
                """;
            packageCommand.Parameters.Add("$id", SqliteType.Text);
            packageCommand.Parameters.Add("$ecosystem", SqliteType.Text);
            packageCommand.Parameters.Add("$package", SqliteType.Text);
            packageCommand.Prepare();
        }

        public async Task UpsertAsync(
            OsvImportRecord record,
            CancellationToken cancellationToken)
        {
            advisoryCommand.Parameters["$id"].Value = record.Id;
            advisoryCommand.Parameters["$modified"].Value =
                (object?)record.ModifiedAt ?? DBNull.Value;
            advisoryCommand.Parameters["$withdrawn"].Value =
                (object?)record.WithdrawnAt ?? DBNull.Value;
            advisoryCommand.Parameters["$json"].Value = record.RawJson;
            await advisoryCommand.ExecuteNonQueryAsync(cancellationToken);

            packageCommand.Parameters["$id"].Value = record.Id;
            packageCommand.Parameters["$ecosystem"].Value =
                SqliteOsvAdvisoryStore.Normalize(record.ImportedEcosystem);
            foreach (var package in record.Packages)
            {
                packageCommand.Parameters["$package"].Value = package;
                await packageCommand.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await advisoryCommand.DisposeAsync();
            await packageCommand.DisposeAsync();
        }
    }
}

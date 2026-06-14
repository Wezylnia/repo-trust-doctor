using System.Globalization;
using RepoTrustDoctor.Infrastructure.LocalData;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public sealed record OsvEcosystemRefreshResult(
    string Ecosystem,
    string Mode,
    int AdvisoryCount);

public sealed class OsvFeedUpdater(
    LocalIntelligenceOptions options,
    SqliteOsvAdvisoryStore store,
    OsvDumpImporter importer,
    IOsvFeedSource source,
    TimeProvider? timeProvider = null)
{
    private const int MaximumIncrementalAdvisories = 10_000;
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<OsvEcosystemRefreshResult>> RefreshAsync(
        CancellationToken cancellationToken)
    {
        var results = new List<OsvEcosystemRefreshResult>();
        foreach (var ecosystem in options.OsvEcosystems)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await RefreshEcosystemAsync(ecosystem, cancellationToken));
        }

        return results;
    }

    public async Task<OsvEcosystemRefreshResult> RefreshEcosystemAsync(
        string ecosystem,
        CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var lastFull = ParseDate(await store.GetStateAsync(
            SqliteOsvAdvisoryStore.LastFullKey(ecosystem),
            cancellationToken));
        if (lastFull is null || now - lastFull >= options.FullOsvRefreshInterval)
        {
            return await FullRefreshAsync(ecosystem, now, cancellationToken);
        }

        var lastIncremental = ParseDate(await store.GetStateAsync(
                                  SqliteOsvAdvisoryStore.LastIncrementalKey(ecosystem),
                                  cancellationToken)) ??
                              lastFull.Value;
        var modified = ParseModifiedIndex(
                await source.GetModifiedIndexAsync(ecosystem, cancellationToken))
            .Where(item => item.ModifiedAt > lastIncremental)
            .OrderBy(item => item.ModifiedAt)
            .ToArray();
        if (modified.Length > MaximumIncrementalAdvisories)
        {
            return await FullRefreshAsync(ecosystem, now, cancellationToken);
        }

        var imported = 0;
        foreach (var item in modified)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var json = await source.GetAdvisoryAsync(
                ecosystem,
                item.AdvisoryId,
                cancellationToken);
            if (await importer.ImportAdvisoryAsync(ecosystem, json, cancellationToken))
            {
                imported++;
            }
        }

        await store.SetStateAsync(
            SqliteOsvAdvisoryStore.LastIncrementalKey(ecosystem),
            now.ToString("O"),
            now,
            cancellationToken);
        return new OsvEcosystemRefreshResult(ecosystem, "incremental", imported);
    }

    public static IReadOnlyList<OsvModifiedAdvisory> ParseModifiedIndex(string csv)
    {
        var results = new List<OsvModifiedAdvisory>();
        foreach (var rawLine in csv.Split(
                     ['\r', '\n'],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = rawLine.IndexOf(',');
            if (separator <= 0)
            {
                continue;
            }

            var first = rawLine[..separator].Trim().Trim('"');
            var second = rawLine[(separator + 1)..].Trim().Trim('"');
            var firstIsDate = TryParseDate(first, out var firstDate);
            var secondIsDate = TryParseDate(second, out var secondDate);
            if (firstIsDate == secondIsDate)
            {
                continue;
            }

            results.Add(firstIsDate
                ? new OsvModifiedAdvisory(second, firstDate)
                : new OsvModifiedAdvisory(first, secondDate));
        }

        return results;
    }

    private async Task<OsvEcosystemRefreshResult> FullRefreshAsync(
        string ecosystem,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var archive = await source.OpenFullArchiveAsync(
            ecosystem,
            cancellationToken);
        var result = await importer.ImportFullArchiveAsync(
            ecosystem,
            archive,
            now,
            cancellationToken);
        return new OsvEcosystemRefreshResult(
            ecosystem,
            "full",
            result.AdvisoryCount);
    }

    private static DateTimeOffset? ParseDate(string? value) =>
        DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;

    private static bool TryParseDate(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,
            out parsed);
}

public sealed record OsvModifiedAdvisory(
    string AdvisoryId,
    DateTimeOffset ModifiedAt);

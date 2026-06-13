using System.Text.Json;
using System.Text.Json.Serialization;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public interface IOsvAdvisoryClient
{
    bool SupportsEcosystem(DependencyEcosystem ecosystem) => true;

    Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken);

    async Task<OsvBatchQueryResult> QueryBatchAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        var results = new List<OsvPackageQueryResult>(packages.Count);
        foreach (var package in packages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(new OsvPackageQueryResult(
                package,
                await QueryAsync(package, cancellationToken)));
        }

        return new OsvBatchQueryResult(results, true, []);
    }
}

public sealed record OsvPackageQueryResult(
    DependencyPackageInfo Package,
    IReadOnlyList<VulnerabilityAdvisory> Advisories);

public sealed record OsvBatchQueryResult(
    IReadOnlyList<OsvPackageQueryResult> Packages,
    bool QuerySucceeded,
    IReadOnlyList<string> Warnings);

public sealed class OsvAdvisoryClient(SafeHttpLookup lookup) : IOsvAdvisoryClient
{
    private const int MaxConcurrentAdvisoryLookups = 8;

    public bool SupportsEcosystem(DependencyEcosystem ecosystem) =>
        OsvEcosystemNames.GetName(ecosystem) is not null;

    public async Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(package.Version))
        {
            return [];
        }

        var ecosystem = OsvEcosystemNames.GetName(package.Ecosystem);

        if (ecosystem is null)
        {
            return [];
        }

        var payload = JsonSerializer.Serialize(new
        {
            version = package.Version,
            package = new { name = package.Name, ecosystem }
        });
        var result = await lookup.PostJsonAsync(new Uri("https://api.osv.dev/v1/query"), payload, cancellationToken);
        return result.Success && result.Body is not null
            ? Parse(result.Body)
            : [];
    }

    public async Task<OsvBatchQueryResult> QueryBatchAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        if (packages.Count == 0)
        {
            return new OsvBatchQueryResult([], true, []);
        }

        var advisoryIds = packages
            .Select(_ => new HashSet<string>(StringComparer.OrdinalIgnoreCase))
            .ToArray();
        var seenPageTokens = packages
            .Select(_ => new HashSet<string>(StringComparer.Ordinal))
            .ToArray();
        var pendingQueries = packages
            .Select((package, index) => new PendingQuery(index, package, null))
            .ToArray();

        while (pendingQueries.Length > 0)
        {
            var response = await QueryBatchPageAsync(pendingQueries, cancellationToken);
            if (!response.Success || response.Body is null)
            {
                return CreatePartialBatchResult(
                    packages,
                    advisoryIds,
                    response.ErrorMessage ?? "OSV batch query failed.");
            }

            IReadOnlyList<OsvBatchPageResult> pageResults;
            try
            {
                pageResults = ParseBatchPage(response.Body, pendingQueries.Length);
            }
            catch (JsonException ex)
            {
                return CreatePartialBatchResult(
                    packages,
                    advisoryIds,
                    $"Could not parse OSV batch response: {ex.Message}");
            }

            var nextQueries = new List<PendingQuery>();
            for (var index = 0; index < pageResults.Count; index++)
            {
                var query = pendingQueries[index];
                var page = pageResults[index];
                advisoryIds[query.OriginalIndex].UnionWith(page.AdvisoryIds);

                if (string.IsNullOrWhiteSpace(page.NextPageToken))
                {
                    continue;
                }

                if (!seenPageTokens[query.OriginalIndex].Add(page.NextPageToken))
                {
                    return CreatePartialBatchResult(
                        packages,
                        advisoryIds,
                        $"OSV repeated a pagination token for {query.Package.Ecosystem}:{query.Package.Name}.");
                }

                nextQueries.Add(query with { PageToken = page.NextPageToken });
            }

            pendingQueries = nextQueries.ToArray();
        }

        var uniqueIds = advisoryIds
            .SelectMany(ids => ids)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var details = await FetchAdvisoriesAsync(uniqueIds, cancellationToken);
        var warnings = details
            .Where(pair => pair.Value.Warning is not null)
            .Select(pair => pair.Value.Warning!)
            .ToArray();
        var results = packages
            .Select((package, index) =>
                new OsvPackageQueryResult(
                    package,
                    advisoryIds[index]
                        .Select(id => CreateAdvisoryForPackage(id, package, details))
                        .ToArray()))
            .ToArray();

        return new OsvBatchQueryResult(results, true, warnings);
    }

    private async Task<SafeLookupResult> QueryBatchPageAsync(
        IReadOnlyList<PendingQuery> queries,
        CancellationToken cancellationToken)
    {
        var payloadQueries = queries
            .Select(query => new
            {
                version = query.Package.Version,
                package = new
                {
                    name = query.Package.Name,
                    ecosystem = OsvEcosystemNames.GetName(query.Package.Ecosystem)
                },
                page_token = query.PageToken
            })
            .ToArray();
        var payload = JsonSerializer.Serialize(
            new { queries = payloadQueries },
            new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });

        return await lookup.PostJsonAsync(
            new Uri("https://api.osv.dev/v1/querybatch"),
            payload,
            cancellationToken);
    }

    private static OsvBatchQueryResult CreatePartialBatchResult(
        IReadOnlyList<DependencyPackageInfo> packages,
        IReadOnlyList<HashSet<string>> advisoryIds,
        string warning)
    {
        var results = packages
            .Select((package, index) =>
                new OsvPackageQueryResult(
                    package,
                    advisoryIds[index]
                        .Select(OsvAdvisoryParser.CreateFallback)
                        .ToArray()))
            .ToArray();
        return new OsvBatchQueryResult(results, false, [warning]);
    }

    public static IReadOnlyList<VulnerabilityAdvisory> Parse(string json) =>
        OsvAdvisoryParser.ParseQueryResponse(json);

    public static VulnerabilityAdvisory ParseAdvisory(string json) =>
        OsvAdvisoryParser.ParseAdvisory(json);

    public static IReadOnlyList<IReadOnlyList<string>> ParseBatchAdvisoryIds(string json, int expectedResultCount)
    {
        return ParseBatchPage(json, expectedResultCount)
            .Select(result => result.AdvisoryIds)
            .ToArray();
    }

    private static IReadOnlyList<OsvBatchPageResult> ParseBatchPage(
        string json,
        int expectedResultCount)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("results", out var results) ||
            results.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("OSV batch response does not contain a results array.");
        }

        var parsed = results
            .EnumerateArray()
            .Select(result => new OsvBatchPageResult(
                result.TryGetProperty("vulns", out var vulns) && vulns.ValueKind == JsonValueKind.Array
                    ? vulns
                        .EnumerateArray()
                        .Select(vulnerability => ReadString(vulnerability, "id"))
                        .Where(id => !string.IsNullOrWhiteSpace(id))
                        .Select(id => id!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray()
                    : [],
                ReadString(result, "next_page_token")))
            .ToList();

        if (parsed.Count != expectedResultCount)
        {
            throw new JsonException(
                $"OSV batch response contains {parsed.Count} results for {expectedResultCount} queries.");
        }

        return parsed;
    }

    private static VulnerabilityAdvisory CreateAdvisoryForPackage(
        string id,
        DependencyPackageInfo package,
        IReadOnlyDictionary<string, AdvisoryLookupResult> details)
    {
        if (!details.TryGetValue(id, out var detail) || detail.Json is null)
        {
            return OsvAdvisoryParser.CreateFallback(id);
        }

        return OsvAdvisoryParser.ParseAdvisory(detail.Json, package);
    }

    private async Task<IReadOnlyDictionary<string, AdvisoryLookupResult>> FetchAdvisoriesAsync(
        IReadOnlyList<string> advisoryIds,
        CancellationToken cancellationToken)
    {
        using var throttle = new SemaphoreSlim(MaxConcurrentAdvisoryLookups);
        var tasks = advisoryIds.Select(async id =>
        {
            await throttle.WaitAsync(cancellationToken);
            try
            {
                var result = await lookup.GetStringAsync(
                    new Uri($"https://api.osv.dev/v1/vulns/{Uri.EscapeDataString(id)}"),
                    cancellationToken);
                if (!result.Success || result.Body is null)
                {
                    return new KeyValuePair<string, AdvisoryLookupResult>(
                        id,
                        new AdvisoryLookupResult(
                            null,
                            $"OSV matched advisory {id}, but its details could not be loaded: {result.ErrorMessage ?? "unknown error"}"));
                }

                try
                {
                    using var _ = JsonDocument.Parse(result.Body);
                    return new KeyValuePair<string, AdvisoryLookupResult>(
                        id,
                        new AdvisoryLookupResult(result.Body, null));
                }
                catch (JsonException ex)
                {
                    return new KeyValuePair<string, AdvisoryLookupResult>(
                        id,
                        new AdvisoryLookupResult(
                            null,
                            $"OSV matched advisory {id}, but its details could not be parsed: {ex.Message}"));
                }
            }
            finally
            {
                throttle.Release();
            }
        });

        return (await Task.WhenAll(tasks))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
    }

    private sealed record AdvisoryLookupResult(
        string? Json,
        string? Warning);

    private sealed record PendingQuery(
        int OriginalIndex,
        DependencyPackageInfo Package,
        string? PageToken);

    private sealed record OsvBatchPageResult(
        IReadOnlyList<string> AdvisoryIds,
        string? NextPageToken);
}

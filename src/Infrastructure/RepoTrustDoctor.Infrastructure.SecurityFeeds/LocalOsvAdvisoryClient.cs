using System.Text.Json;
using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public sealed class LocalOsvAdvisoryClient(
    SqliteOsvAdvisoryStore store,
    IOsvAdvisoryClient? onlineFallback) : IOsvAdvisoryClient
{
    public bool SupportsEcosystem(DependencyEcosystem ecosystem) =>
        OsvEcosystemNames.GetName(ecosystem) is not null &&
        (onlineFallback?.SupportsEcosystem(ecosystem) ?? true);

    public async Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        try
        {
            var ecosystem = OsvEcosystemNames.GetName(package.Ecosystem);
            var ready = ecosystem is not null &&
                        await store.IsEcosystemReadyAsync(ecosystem, cancellationToken);
            var candidates = ready
                ? await store.GetCandidatesAsync(package, cancellationToken)
                : [];
            var local = QueryLocal(package, ecosystem, ready, candidates);
            if (local.Complete)
            {
                return local.Advisories;
            }

            return onlineFallback is null
                ? local.Advisories
                : await onlineFallback.QueryAsync(package, cancellationToken);
        }
        catch (Exception ex) when (IsLocalStoreFailure(ex))
        {
            return onlineFallback is null
                ? []
                : await onlineFallback.QueryAsync(package, cancellationToken);
        }
    }

    public async Task<OsvBatchQueryResult> QueryBatchAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        try
        {
            return await QueryBatchCoreAsync(packages, cancellationToken);
        }
        catch (Exception ex) when (IsLocalStoreFailure(ex))
        {
            const string warning =
                "The local OSV SQLite index could not be read; online fallback was used.";
            if (onlineFallback is null)
            {
                return new OsvBatchQueryResult(
                    packages.Select(package => new OsvPackageQueryResult(package, []))
                        .ToArray(),
                    false,
                    [warning])
                {
                    CompletedPackageCount = 0
                };
            }

            var online = await onlineFallback.QueryBatchAsync(packages, cancellationToken);
            return online with
            {
                Warnings = online.Warnings
                    .Append(warning)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                LocalPackageCount = 0,
                OnlinePackageCount = packages.Count
            };
        }
    }

    private async Task<OsvBatchQueryResult> QueryBatchCoreAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        var results = new OsvPackageQueryResult?[packages.Count];
        var fallbackPackages = new List<DependencyPackageInfo>();
        var fallbackIndexes = new List<int>();
        var warnings = new List<string>();
        var readiness = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var ecosystem in packages
                     .Select(package => OsvEcosystemNames.GetName(package.Ecosystem))
                     .Where(ecosystem => ecosystem is not null)
                     .Select(ecosystem => ecosystem!)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            readiness[ecosystem] = await store.IsEcosystemReadyAsync(ecosystem, cancellationToken);
        }

        var localIndexes = packages
            .Select((package, index) => new
            {
                Package = package,
                Index = index,
                Ecosystem = OsvEcosystemNames.GetName(package.Ecosystem)
            })
            .Where(item =>
                item.Ecosystem is not null &&
                readiness.GetValueOrDefault(item.Ecosystem))
            .ToArray();
        var localCandidates = await store.GetCandidatesAsync(
            localIndexes.Select(item => item.Package).ToArray(),
            cancellationToken);
        var candidatesByIndex = localIndexes
            .Select((item, index) => new { item.Index, Candidates = localCandidates[index] })
            .ToDictionary(item => item.Index, item => item.Candidates);

        for (var index = 0; index < packages.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ecosystem = OsvEcosystemNames.GetName(packages[index].Ecosystem);
            var ready = ecosystem is not null && readiness.GetValueOrDefault(ecosystem);
            var local = QueryLocal(
                packages[index],
                ecosystem,
                ready,
                candidatesByIndex.GetValueOrDefault(index) ?? []);
            if (local.Complete)
            {
                results[index] = new OsvPackageQueryResult(packages[index], local.Advisories);
                continue;
            }

            fallbackPackages.Add(packages[index]);
            fallbackIndexes.Add(index);
            results[index] = new OsvPackageQueryResult(
                packages[index],
                local.Advisories);
            if (local.Warning is not null)
            {
                warnings.Add(local.Warning);
            }
        }

        var querySucceeded = true;
        var completedPackageCount = packages.Count - fallbackPackages.Count;
        if (fallbackPackages.Count > 0)
        {
            if (onlineFallback is null)
            {
                querySucceeded = false;
            }
            else
            {
                var online = await onlineFallback.QueryBatchAsync(
                    fallbackPackages,
                    cancellationToken);
                querySucceeded = online.QuerySucceeded;
                completedPackageCount += GetCompletedPackageCount(online);
                warnings.AddRange(online.Warnings);
                for (var index = 0; index < online.Packages.Count; index++)
                {
                    results[fallbackIndexes[index]] = online.Packages[index];
                }
            }
        }

        return new OsvBatchQueryResult(
            results.Select((result, index) =>
                    result ?? new OsvPackageQueryResult(packages[index], []))
                .ToArray(),
            querySucceeded,
            warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray())
        {
            CompletedPackageCount = completedPackageCount,
            LocalPackageCount = packages.Count - fallbackPackages.Count,
            OnlinePackageCount = onlineFallback is null ? 0 : fallbackPackages.Count
        };
    }

    private static LocalQueryResult QueryLocal(
        DependencyPackageInfo package,
        string? ecosystem,
        bool ecosystemReady,
        IReadOnlyList<OsvStoredAdvisory> candidates)
    {
        if (ecosystem is null ||
            !ecosystemReady)
        {
            return new LocalQueryResult(
                false,
                [],
                $"Local OSV data is not ready for {ecosystem ?? package.Ecosystem.ToString()}; online fallback is required.");
        }

        var advisories = new List<VulnerabilityAdvisory>();
        string? warning = null;
        foreach (var candidate in candidates)
        {
            try
            {
                using var document = JsonDocument.Parse(candidate.RawJson);
                var match = OsvAffectedVersionMatcher.Match(document.RootElement, package);
                if (match == OsvVersionMatch.Indeterminate)
                {
                    warning ??=
                        $"Local OSV range evaluation was inconclusive for {package.Ecosystem}:{package.Name}:{package.Version}; online fallback is required.";
                    continue;
                }

                if (match == OsvVersionMatch.Affected)
                {
                    advisories.Add(OsvAdvisoryParser.ParseAdvisory(candidate.RawJson, package));
                }
            }
            catch (JsonException)
            {
                warning ??=
                    $"Local OSV advisory {candidate.Id} is malformed; online fallback is required.";
            }
        }

        return new LocalQueryResult(warning is null, advisories, warning);
    }

    private sealed record LocalQueryResult(
        bool Complete,
        IReadOnlyList<VulnerabilityAdvisory> Advisories,
        string? Warning);

    private static bool IsLocalStoreFailure(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException;

    private static int GetCompletedPackageCount(OsvBatchQueryResult result) =>
        result.CompletedPackageCount > 0 || result.Packages.Count == 0
            ? result.CompletedPackageCount
            : result.QuerySucceeded
                ? result.Packages.Count
                : 0;
}

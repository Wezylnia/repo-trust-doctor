using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.Infrastructure.Scanning;

public sealed record LocalIntelligenceRefreshResult(
    RegistryRefreshResult Registry,
    IReadOnlyList<OsvEcosystemRefreshResult> Osv);

public sealed class LocalIntelligenceRefreshCoordinator : IDisposable
{
    private readonly RegistryMetadataRefresher registryRefresher;
    private readonly OsvFeedUpdater osvUpdater;
    private readonly HttpOsvFeedSource osvSource;

    public LocalIntelligenceRefreshCoordinator(LocalIntelligenceOptions options)
    {
        var database = new LocalIntelligenceDatabase(options);
        var cache = new SqlitePackageMetadataCache(database);
        var packageLookup = new SafeHttpLookup(
            ["api.nuget.org", "registry.npmjs.org", "pypi.org", "search.maven.org"]);
        IPackageMetadataClient[] clients =
        [
            new NuGetPackageMetadataClient(packageLookup),
            new NpmPackageMetadataClient(packageLookup),
            new PyPiPackageMetadataClient(packageLookup),
            new MavenCentralPackageMetadataClient(packageLookup)
        ];
        registryRefresher = new RegistryMetadataRefresher(
            cache,
            clients,
            options.RegistryCacheTtl,
            options.RegistryRefreshBatchSize,
            options.RegistryRefreshConcurrency);

        var store = new SqliteOsvAdvisoryStore(database);
        osvSource = new HttpOsvFeedSource();
        osvUpdater = new OsvFeedUpdater(
            options,
            store,
            new OsvDumpImporter(store),
            osvSource);
    }

    public async Task<LocalIntelligenceRefreshResult> RefreshAsync(
        CancellationToken cancellationToken)
    {
        var registryTask = registryRefresher.RefreshExpiredAsync(cancellationToken);
        var osvTask = osvUpdater.RefreshAsync(cancellationToken);
        await Task.WhenAll(registryTask, osvTask);
        return new LocalIntelligenceRefreshResult(
            await registryTask,
            await osvTask);
    }

    public void Dispose() => osvSource.Dispose();
}

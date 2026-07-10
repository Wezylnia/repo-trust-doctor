using System.Collections.Concurrent;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Analyzers.DockerCompose;
using RepoTrustDoctor.Analyzers.Kubernetes;
using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analyzers.GitLabCi;
using RepoTrustDoctor.Analyzers.AzurePipelines;
using RepoTrustDoctor.Analyzers.CircleCi;
using RepoTrustDoctor.Analyzers.Terraform;
using RepoTrustDoctor.Analyzers.PackageRegistryConfig;
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Git;
using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;
using RepoTrustDoctor.Scoring;
using RepoTrustDoctor.Shared;

namespace RepoTrustDoctor.Infrastructure.Scanning;

public sealed class DefaultRepositoryScanRunner : IRepositoryScanRunner
{
    private static readonly TimeSpan ScanCacheTtl = TimeSpan.FromSeconds(30);
    private readonly IReadOnlyList<IRepositoryAnalyzer> analyzers;
    private readonly ConcurrentDictionary<ScanCacheKey, CachedScan> scanCache = new();

    public DefaultRepositoryScanRunner()
        : this(LocalIntelligenceOptions.CreateDefault())
    {
    }

    public DefaultRepositoryScanRunner(LocalIntelligenceOptions localOptions)
        : this(CreateAnalyzers(localOptions))
    {
    }

    internal DefaultRepositoryScanRunner(IReadOnlyList<IRepositoryAnalyzer> analyzers)
    {
        this.analyzers = analyzers;
    }

    public async Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
    {
        var cacheKey = options.UseIncrementalCache
            ? await TryCreateCacheKeyAsync(options, cancellationToken)
            : null;
        if (cacheKey is not null &&
            scanCache.TryGetValue(cacheKey, out var cached) &&
            DateTimeOffset.UtcNow - cached.StoredAt <= ScanCacheTtl)
        {
            var now = DateTimeOffset.UtcNow;
            options.Progress?.Invoke(new ScanExecutionProgress(
                RepoTrustDoctor.Contracts.ScanLifecycleState.Reporting,
                "Reused the completed analysis for this unchanged revision.",
                cached.Scan.Modules,
                cached.Scan.Modules.Count));
            return cached.Scan with
            {
                Id = Guid.NewGuid(),
                StartedAt = now,
                CompletedAt = now,
                Artifacts = WithCacheMarker(cached.Scan.Artifacts)
            };
        }

        options.Progress?.Invoke(new ScanExecutionProgress(
            RepoTrustDoctor.Contracts.ScanLifecycleState.PreparingRepository,
            "Preparing a safe repository workspace."));
        using var workspace = await PrepareWorkspaceAsync(options.Target, cancellationToken);
        var orchestrator = new ScanOrchestrator(
            analyzers,
            new AnalyzerExecutor(),
            new TrustScorer());
        var scan = await orchestrator.RunAsync(
            options.Target,
            workspace.Path,
            options.Depth,
            options.TrustProfile,
            cancellationToken,
            (modules, total) => options.Progress?.Invoke(new ScanExecutionProgress(
                MapProgressState(options.Depth, modules.Count, total),
                $"Analyzed {modules.Count} of {total} modules.",
                modules,
                total)));
        if (cacheKey is not null)
        {
            scanCache[cacheKey] = new CachedScan(scan, DateTimeOffset.UtcNow);
            PruneScanCache();
        }

        return scan;
    }

    private async Task<ScanCacheKey?> TryCreateCacheKeyAsync(
        ScanRequestOptions options,
        CancellationToken cancellationToken)
    {
        var isRemote = options.Target.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var revision = isRemote
            ? await RepositoryWorkspace.TryResolveRemoteHeadAsync(options.Target, cancellationToken)
            : await RepositoryWorkspace.TryResolveCleanLocalHeadAsync(options.Target, cancellationToken);
        if (revision is null)
        {
            return null;
        }

        var analyzerContract = string.Join(',', analyzers.Select(analyzer => analyzer.Id));
        return new ScanCacheKey(
            options.Target,
            revision,
            options.Depth,
            options.TrustProfile,
            ProductInfo.Version,
            analyzerContract);
    }

    private void PruneScanCache()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var item in scanCache)
        {
            if (now - item.Value.StoredAt > ScanCacheTtl)
            {
                scanCache.TryRemove(item.Key, out _);
            }
        }
    }

    private static IReadOnlyDictionary<string, object> WithCacheMarker(
        IReadOnlyDictionary<string, object>? artifacts)
    {
        var result = artifacts is null
            ? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, object>(artifacts, StringComparer.OrdinalIgnoreCase);
        result["scan.cache.hit"] = true;
        return result;
    }

    private static RepoTrustDoctor.Contracts.ScanLifecycleState MapProgressState(
        AnalysisDepth depth,
        int completed,
        int total)
    {
        if (depth == AnalysisDepth.Fast)
        {
            return RepoTrustDoctor.Contracts.ScanLifecycleState.RunningFastModules;
        }

        var ratio = total == 0 ? 0 : (double)completed / total;
        if (ratio < 0.35)
        {
            return RepoTrustDoctor.Contracts.ScanLifecycleState.RunningStaticAnalyzers;
        }

        if (depth == AnalysisDepth.Standard || ratio < 0.72)
        {
            return RepoTrustDoctor.Contracts.ScanLifecycleState.RunningDependencyAnalyzers;
        }

        return RepoTrustDoctor.Contracts.ScanLifecycleState.RunningSecurityAnalyzers;
    }

    public static IReadOnlyList<IRepositoryAnalyzer> CreateAnalyzers(
        LocalIntelligenceOptions? localOptions = null)
    {
        localOptions ??= LocalIntelligenceOptions.CreateDefault();
        var packageLookup = new SafeHttpLookup(
            ["api.nuget.org", "registry.npmjs.org", "pypi.org", "search.maven.org"]);
        var osvLookup = new SafeHttpLookup(["api.osv.dev"]);
        var localDatabase = localOptions.RegistryCacheEnabled || localOptions.LocalOsvEnabled
            ? new LocalIntelligenceDatabase(localOptions)
            : null;
        var metadataClients = CreateMetadataClients(packageLookup, localOptions, localDatabase);
        var onlineOsvClient = new OsvAdvisoryClient(osvLookup);
        IOsvAdvisoryClient osvClient = localOptions.LocalOsvEnabled && localDatabase is not null
            ? new LocalOsvAdvisoryClient(
                new SqliteOsvAdvisoryStore(localDatabase),
                localOptions.OsvOnlineFallbackEnabled ? onlineOsvClient : null)
            : onlineOsvClient;
        return
        [
            new RepositoryHealthAnalyzer(),
            new GitHubMetadataAnalyzer(),
            new WorkspaceAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new GitLabCiAnalyzer(),
            new AzurePipelinesAnalyzer(),
            new CircleCiAnalyzer(),
            new TerraformAnalyzer(),
            new PackageRegistryConfigAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer(),
            new DockerComposeAnalyzer(),
            new KubernetesAnalyzer(),
            new DependencyInventoryAnalyzer(),
            new ReleaseEvidenceAnalyzer(),
            new EvidenceImportAnalyzer(),
            new ReleaseIntegrityAnalyzer(),
            new CoverageImportAnalyzer(),
            new CodeCriticalityAnalyzer(),
            new CoverageCriticalityAnalyzer(),
            new PublicApiAnalyzer(),
            new ImportGraphAnalyzer(),
            new FrameworkRouteAnalyzer(),
            new PackageMetadataAnalyzer(metadataClients),
            new PackageFreshnessAnalyzer(),
            new DependencyVulnerabilityAnalyzer(osvClient),
            new DependencyLicenseAnalyzer(),
            new PackageOriginAnalyzer(),
            new DependencyConsistencyAnalyzer()
        ];
    }

    private static IReadOnlyCollection<IPackageMetadataClient> CreateMetadataClients(
        SafeHttpLookup packageLookup,
        LocalIntelligenceOptions options,
        LocalIntelligenceDatabase? localDatabase)
    {
        IPackageMetadataClient[] clients =
        [
            new NuGetPackageMetadataClient(packageLookup),
            new NpmPackageMetadataClient(packageLookup),
            new PyPiPackageMetadataClient(packageLookup),
            new MavenCentralPackageMetadataClient(packageLookup)
        ];
        if (!options.RegistryCacheEnabled || localDatabase is null)
        {
            return clients;
        }

        var cache = new SqlitePackageMetadataCache(localDatabase);
        return clients
            .Select(client => (IPackageMetadataClient)new CachingPackageMetadataClient(
                client,
                cache,
                options.RegistryCacheTtl))
            .ToArray();
    }

    private static Task<RepositoryWorkspace> PrepareWorkspaceAsync(string target, CancellationToken cancellationToken)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return RepositoryWorkspace.CloneFromUrlAsync(target, cancellationToken);
        }

        return Task.FromResult(RepositoryWorkspace.ForLocalPath(target));
    }

    private sealed record ScanCacheKey(
        string Target,
        string Revision,
        AnalysisDepth Depth,
        TrustProfile TrustProfile,
        string ToolVersion,
        string AnalyzerContract);

    private sealed record CachedScan(RepositoryScan Scan, DateTimeOffset StoredAt);
}

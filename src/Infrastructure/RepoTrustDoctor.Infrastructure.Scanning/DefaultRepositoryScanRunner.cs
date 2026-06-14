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

namespace RepoTrustDoctor.Infrastructure.Scanning;

public sealed class DefaultRepositoryScanRunner : IRepositoryScanRunner
{
    private readonly LocalIntelligenceOptions localOptions;

    public DefaultRepositoryScanRunner()
        : this(LocalIntelligenceOptions.CreateDefault())
    {
    }

    public DefaultRepositoryScanRunner(LocalIntelligenceOptions localOptions)
    {
        this.localOptions = localOptions;
    }

    public async Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
    {
        using var workspace = await PrepareWorkspaceAsync(options.Target, cancellationToken);
        var orchestrator = new ScanOrchestrator(
            CreateAnalyzers(localOptions),
            new AnalyzerExecutor(),
            new TrustScorer());
        return await orchestrator.RunAsync(options.Target, workspace.Path, options.Depth, options.TrustProfile, cancellationToken);
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
            new PackageOriginAnalyzer()
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
}

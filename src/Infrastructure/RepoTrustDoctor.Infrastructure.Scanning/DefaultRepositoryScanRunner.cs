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
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Git;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;
using RepoTrustDoctor.Scoring;

namespace RepoTrustDoctor.Infrastructure.Scanning;

public sealed class DefaultRepositoryScanRunner : IRepositoryScanRunner
{
    public async Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
    {
        using var workspace = await PrepareWorkspaceAsync(options.Target, cancellationToken);
        var orchestrator = new ScanOrchestrator(CreateAnalyzers(), new AnalyzerExecutor(), new TrustScorer());
        return await orchestrator.RunAsync(options.Target, workspace.Path, options.Depth, options.TrustProfile, cancellationToken);
    }

    public static IReadOnlyList<IRepositoryAnalyzer> CreateAnalyzers()
    {
        var packageLookup = new SafeHttpLookup(["api.nuget.org", "registry.npmjs.org", "pypi.org"]);
        var osvLookup = new SafeHttpLookup(["api.osv.dev"]);
        return
        [
            new RepositoryHealthAnalyzer(),
            new WorkspaceAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new GitLabCiAnalyzer(),
            new AzurePipelinesAnalyzer(),
            new CircleCiAnalyzer(),
            new TerraformAnalyzer(),
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
            new PackageMetadataAnalyzer(
            [
                new NuGetPackageMetadataClient(packageLookup),
                new NpmPackageMetadataClient(packageLookup),
                new PyPiPackageMetadataClient(packageLookup),
                new MavenCentralPackageMetadataClient(packageLookup)
            ]),
            new PackageFreshnessAnalyzer(),
            new DependencyVulnerabilityAnalyzer(new OsvAdvisoryClient(osvLookup)),
            new DependencyLicenseAnalyzer(),
            new PackageOriginAnalyzer()
        ];
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

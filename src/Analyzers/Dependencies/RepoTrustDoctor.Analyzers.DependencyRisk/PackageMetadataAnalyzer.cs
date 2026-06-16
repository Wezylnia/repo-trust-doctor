using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

public sealed class PackageMetadataAnalyzer : IRepositoryAnalyzer
{
    private static readonly TimeSpan DefaultLookupBudget = TimeSpan.FromSeconds(40);
    private const int MaxConcurrentMetadataLookups = 8;
    private readonly IReadOnlyCollection<IPackageMetadataClient> clients;
    private readonly TimeSpan lookupBudget;

    public PackageMetadataAnalyzer(IReadOnlyCollection<IPackageMetadataClient> clients)
        : this(clients, DefaultLookupBudget)
    {
    }

    internal PackageMetadataAnalyzer(
        IReadOnlyCollection<IPackageMetadataClient> clients,
        TimeSpan lookupBudget)
    {
        this.clients = clients;
        this.lookupBudget = lookupBudget;
    }

    public string Id => "dependency-metadata";
    public string DisplayName => "Package Registry Metadata";
    public AnalysisCategory Category => AnalysisCategory.Dependencies;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [DependencyInventoryArtifact.ArtifactKey];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.NetworkLookup;
    public TimeSpan Timeout => TimeSpan.FromSeconds(45);
    public IReadOnlyCollection<RuleMetadata> Rules => [];

    public async Task<AnalyzerResult> AnalyzeAsync(
        AnalysisContext context,
        CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<DependencyInventoryArtifact>(
                DependencyInventoryArtifact.ArtifactKey,
                out var inventory) ||
            inventory is null)
        {
            return new AnalyzerResult(ModuleStatus.Skipped, []);
        }

        var supportedEcosystems = clients
            .Select(client => client.Ecosystem)
            .ToHashSet();
        var candidates = DistinctPackagesForLookup(inventory.Packages
                .Where(package =>
                    package.IsDirect &&
                    package.IsVersionPinned &&
                    !string.IsNullOrWhiteSpace(package.Version) &&
                    DependencyRiskPathFilters.IsRegistryLookupEligible(package) &&
                    !DependencyRiskPathFilters.IsLikelyExampleOrTestManifest(package.ManifestPath)))
            .ToArray();
        var packages = candidates
            .Where(package => supportedEcosystems.Contains(package.Ecosystem))
            .ToArray();

        var lookupResults = await QueryMetadataAsync(packages, cancellationToken);
        var metadata = lookupResults.Results
            .Where(item =>
                item.Result.Status == PackageMetadataLookupStatus.Found &&
                item.Result.Metadata is not null)
            .Select(item => WithDependencyContext(item.Result.Metadata!, item.Package))
            .ToArray();
        var warnings = BuildWarnings(lookupResults);

        var reliableCount = lookupResults.Results.Count(item =>
            item.Result.Status is PackageMetadataLookupStatus.Found or
                PackageMetadataLookupStatus.NotFound);
        var transientFailureCount = lookupResults.Results.Count(item =>
            item.Result.Status == PackageMetadataLookupStatus.TransientFailure ||
            item.Result.IsStale && IsTransientError(item.Result.ErrorKind));
        var invalidResponseCount = CountStatus(
            lookupResults.Results,
            PackageMetadataLookupStatus.InvalidResponse);
        var rejectedCount = CountStatus(
            lookupResults.Results,
            PackageMetadataLookupStatus.Rejected);
        var blockedCount = CountStatus(
            lookupResults.Results,
            PackageMetadataLookupStatus.Blocked);

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.metadata.candidate.count"] = candidates.Length.ToString(),
            ["dependency.metadata.supported.count"] = packages.Length.ToString(),
            ["dependency.metadata.unsupported.count"] = (candidates.Length - packages.Length).ToString(),
            ["dependency.metadata.lookup.attempted.count"] = lookupResults.StartedCount.ToString(),
            ["dependency.metadata.lookup.returned.count"] = lookupResults.CompletedCount.ToString(),
            ["dependency.metadata.lookup.completed.count"] = reliableCount.ToString(),
            ["dependency.metadata.lookup.incomplete.count"] = (lookupResults.TotalCount - reliableCount).ToString(),
            ["dependency.metadata.lookup.found.count"] = CountStatus(lookupResults.Results, PackageMetadataLookupStatus.Found).ToString(),
            ["dependency.metadata.lookup.not_found.count"] = CountStatus(lookupResults.Results, PackageMetadataLookupStatus.NotFound).ToString(),
            ["dependency.metadata.lookup.failed.count"] = transientFailureCount.ToString(),
            ["dependency.metadata.lookup.rate_limited.count"] = CountErrorKind(lookupResults.Results, SafeLookupErrorKind.RateLimited).ToString(),
            ["dependency.metadata.lookup.server_error.count"] = CountErrorKind(lookupResults.Results, SafeLookupErrorKind.ServerError).ToString(),
            ["dependency.metadata.lookup.invalid_response.count"] = invalidResponseCount.ToString(),
            ["dependency.metadata.lookup.rejected.count"] = rejectedCount.ToString(),
            ["dependency.metadata.lookup.blocked.count"] = blockedCount.ToString(),
            ["dependency.metadata.lookup.stale_used.count"] = lookupResults.Results.Count(item => item.Result.IsStale).ToString(),
            ["dependency.metadata.package.count"] = metadata.Length.ToString(),
            ["dependency.metadata.cache.hit.count"] = lookupResults.Results.Count(item =>
                item.Result.Source?.StartsWith("sqlite", StringComparison.OrdinalIgnoreCase) == true).ToString(),
            ["dependency.metadata.network.count"] = lookupResults.Results.Count(item =>
                item.Result.Source?.Equals("network", StringComparison.OrdinalIgnoreCase) == true).ToString()
        };
        var artifact = new PackageMetadataArtifact(metadata, metrics);
        return AnalyzerResult.Completed(
            [],
            [new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, artifact)],
            metrics,
            warnings);
    }

    private Task<BoundedLookupResult<PackageMetadataLookup>> QueryMetadataAsync(
        IReadOnlyList<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        return BoundedLookupRunner.RunAsync(
            packages,
            MaxConcurrentMetadataLookups,
            lookupBudget,
            async (package, lookupCancellationToken) =>
            {
                var client = clients.First(client => client.Ecosystem == package.Ecosystem);
                try
                {
                    var result = await client.GetMetadataAsync(package, lookupCancellationToken);
                    return new PackageMetadataLookup(
                        package,
                        result.Source is null ? result with { Source = "network" } : result);
                }
                catch (Exception ex) when (
                    ex is JsonException or InvalidOperationException or FormatException)
                {
                    return new PackageMetadataLookup(
                        package,
                        PackageMetadataLookupResult.Failure(
                            PackageMetadataLookupStatus.InvalidResponse,
                            SafeLookupErrorKind.MalformedResponse,
                            ex.Message) with { Source = "network" });
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException)
                {
                    return new PackageMetadataLookup(
                        package,
                        PackageMetadataLookupResult.Failure(
                            PackageMetadataLookupStatus.TransientFailure,
                            SafeLookupErrorKind.TransportError,
                            ex.Message) with { Source = "network" });
                }
            },
            cancellationToken);
    }

    private List<string> BuildWarnings(BoundedLookupResult<PackageMetadataLookup> lookupResults)
    {
        var warnings = new List<string>();
        AddStatusWarning(
            warnings,
            lookupResults.Results,
            PackageMetadataLookupStatus.TransientFailure,
            "Package metadata lookup failed temporarily");
        AddStatusWarning(
            warnings,
            lookupResults.Results,
            PackageMetadataLookupStatus.InvalidResponse,
            "Package registry returned invalid metadata");
        AddErrorWarning(
            warnings,
            lookupResults.Results,
            SafeLookupErrorKind.RateLimited,
            "Package registry rate-limited metadata lookup");
        AddErrorWarning(
            warnings,
            lookupResults.Results,
            SafeLookupErrorKind.ServerError,
            "Package registry returned a server error");
        AddStatusWarning(
            warnings,
            lookupResults.Results,
            PackageMetadataLookupStatus.Rejected,
            "Package registry rejected metadata lookup");
        AddStatusWarning(
            warnings,
            lookupResults.Results,
            PackageMetadataLookupStatus.Blocked,
            "Package metadata lookup was blocked");

        var stale = lookupResults.Results.Where(item => item.Result.IsStale).ToArray();
        if (stale.Length > 0)
        {
            warnings.Add(
                $"Used stale cached metadata for {stale.Length} package(s) after refresh failures: {FormatPackageSample(stale)}.");
        }

        if (lookupResults.SoftBudgetExceeded)
        {
            warnings.Add(
                $"Package metadata lookup returned results for {lookupResults.CompletedCount} of {lookupResults.StartedCount} attempted packages before the {lookupBudget.TotalSeconds:0}-second soft budget; completed metadata was preserved.");
        }

        return warnings;
    }

    private static void AddStatusWarning(
        ICollection<string> warnings,
        IReadOnlyList<PackageMetadataLookup> lookups,
        PackageMetadataLookupStatus status,
        string message)
    {
        var matching = lookups.Where(item => item.Result.Status == status).ToArray();
        if (matching.Length > 0)
        {
            warnings.Add($"{message} for {matching.Length} package(s): {FormatPackageSample(matching)}.");
        }
    }

    private static string FormatPackageSample(IEnumerable<PackageMetadataLookup> lookups) =>
        string.Join(
            ", ",
            lookups
                .Take(5)
                .Select(item => $"{item.Package.Ecosystem}:{item.Package.Name}"));

    private static void AddErrorWarning(
        ICollection<string> warnings,
        IReadOnlyList<PackageMetadataLookup> lookups,
        SafeLookupErrorKind errorKind,
        string message)
    {
        var matching = lookups.Where(item => item.Result.ErrorKind == errorKind).ToArray();
        if (matching.Length > 0)
        {
            warnings.Add($"{message} for {matching.Length} package(s): {FormatPackageSample(matching)}.");
        }
    }

    private static int CountStatus(
        IReadOnlyList<PackageMetadataLookup> lookups,
        PackageMetadataLookupStatus status) =>
        lookups.Count(item => item.Result.Status == status);

    private static int CountErrorKind(
        IReadOnlyList<PackageMetadataLookup> lookups,
        SafeLookupErrorKind errorKind) =>
        lookups.Count(item => item.Result.ErrorKind == errorKind);

    private static bool IsTransientError(SafeLookupErrorKind? errorKind) =>
        errorKind is SafeLookupErrorKind.Timeout or
            SafeLookupErrorKind.RateLimited or
            SafeLookupErrorKind.ServerError or
            SafeLookupErrorKind.TransportError;

    private static PackageRegistryMetadata WithDependencyContext(
        PackageRegistryMetadata metadata,
        DependencyPackageInfo package)
    {
        var enriched = new Dictionary<string, string>(
            metadata.Metadata ?? new Dictionary<string, string>(),
            StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.scope"] = package.Scope.ToString(),
            ["dependency.manifestPath"] = package.ManifestPath,
            ["dependency.isDirect"] = package.IsDirect.ToString()
        };

        return metadata with { Metadata = enriched };
    }

    internal static IEnumerable<DependencyPackageInfo> DistinctPackagesForLookup(
        IEnumerable<DependencyPackageInfo> packages)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var package in packages)
        {
            var key = BuildLookupKey(package);
            if (seen.Add(key))
            {
                yield return package;
            }
        }
    }

    private static string BuildLookupKey(DependencyPackageInfo package) =>
        string.Join(
            ':',
            package.Ecosystem,
            NormalizePackageNameForLookup(package),
            package.Version ?? string.Empty);

    private static string NormalizePackageNameForLookup(DependencyPackageInfo package) =>
        package.Ecosystem switch
        {
            DependencyEcosystem.Python => NormalizePyPiName(package.Name),
            DependencyEcosystem.NuGet or
            DependencyEcosystem.Npm or
            DependencyEcosystem.Cargo or
            DependencyEcosystem.Composer or
            DependencyEcosystem.Ruby or
            DependencyEcosystem.Pub or
            DependencyEcosystem.Hex => package.Name.ToLowerInvariant(),
            DependencyEcosystem.Go or
            DependencyEcosystem.Maven or
            DependencyEcosystem.Swift => package.Name,
            _ => package.Name.ToLowerInvariant()
        };

    private static string NormalizePyPiName(string name)
    {
        var normalized = name.ToLowerInvariant().Replace('_', '-').Replace('.', '-');
        while (normalized.Contains("--", StringComparison.Ordinal))
        {
            normalized = normalized.Replace("--", "-", StringComparison.Ordinal);
        }

        return normalized;
    }

    private sealed record PackageMetadataLookup(
        DependencyPackageInfo Package,
        PackageMetadataLookupResult Result);
}

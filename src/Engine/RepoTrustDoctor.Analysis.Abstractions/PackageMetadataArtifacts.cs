using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analysis.Abstractions;

public enum PackageLicenseFamily
{
    Unknown,
    Permissive,
    Copyleft,
    Proprietary,
    Other
}

public sealed record NormalizedPackageLicense(
    PackageLicenseFamily Family,
    string? SpdxId,
    string? OriginalExpression,
    bool IsKnown,
    bool IsPolicySensitive);

public sealed record PackageRegistryMetadata(
    DependencyEcosystem Ecosystem,
    string Name,
    string? RequestedVersion,
    string? LatestVersion,
    DateTimeOffset? PublishedAt,
    bool IsDeprecated,
    bool IsYanked,
    string? RepositoryUrl,
    string? HomepageUrl,
    string? LicenseExpression,
    long? DownloadCount,
    string SourceRegistry,
    IReadOnlyDictionary<string, string>? Metadata = null);

public sealed record PackageMetadataArtifact(
    IReadOnlyList<PackageRegistryMetadata> Packages,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "dependency.packageMetadata";
}

public sealed record VulnerabilityAdvisory(
    string Id,
    IReadOnlyList<string> Aliases,
    string Summary,
    Severity Severity,
    IReadOnlyList<string> FixedVersions,
    DateTimeOffset? PublishedAt,
    DateTimeOffset? ModifiedAt);

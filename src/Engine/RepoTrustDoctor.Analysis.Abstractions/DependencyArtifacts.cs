namespace RepoTrustDoctor.Analysis.Abstractions;

public enum DependencyEcosystem
{
    NuGet,
    Npm,
    Python
}

public enum DependencyScope
{
    Production,
    Development,
    Optional,
    Peer,
    Transitive,
    Unknown
}

public sealed record DependencyManifestInfo(
    DependencyEcosystem Ecosystem,
    string FilePath,
    string Kind,
    IReadOnlyDictionary<string, string>? Metadata = null);

public sealed record DependencyLockfileInfo(
    DependencyEcosystem Ecosystem,
    string FilePath,
    string Kind);

public sealed record DependencyPackageSourceInfo(
    DependencyEcosystem Ecosystem,
    string Name,
    string Source,
    string FilePath,
    bool IsLocal = false,
    bool IsSecureTransport = true,
    IReadOnlyDictionary<string, string>? Metadata = null);

public sealed record DependencyPackageInfo(
    DependencyEcosystem Ecosystem,
    string Name,
    string? Version,
    DependencyScope Scope,
    string ManifestPath,
    string? LockfilePath,
    bool IsDirect,
    bool IsVersionPinned,
    bool IsPrerelease,
    IReadOnlyDictionary<string, string>? Metadata = null);

public sealed record DependencyInventoryArtifact(
    IReadOnlyList<DependencyManifestInfo> Manifests,
    IReadOnlyList<DependencyLockfileInfo> Lockfiles,
    IReadOnlyList<DependencyPackageInfo> Packages,
    IReadOnlyList<DependencyPackageSourceInfo> PackageSources,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "dependency.inventory";
}

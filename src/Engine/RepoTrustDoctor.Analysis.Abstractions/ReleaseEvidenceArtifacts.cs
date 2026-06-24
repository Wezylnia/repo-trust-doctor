namespace RepoTrustDoctor.Analysis.Abstractions;

public enum ImportedEvidenceKind
{
    CycloneDx,
    Spdx,
    InToto,
    SlsaProvenance,
    Unknown
}

public sealed record ImportedSbomComponent(
    string? Name,
    string? Version,
    string? PackageUrl);

public sealed record ProvenanceSubject(
    string Name,
    IReadOnlyDictionary<string, string> Digests);

public sealed record ImportedEvidenceFile(
    string FilePath,
    ImportedEvidenceKind Kind,
    string? SpecVersion,
    IReadOnlyList<ImportedSbomComponent> Components,
    IReadOnlyList<ProvenanceSubject> Subjects,
    string? RepositoryIdentity,
    string? CommitIdentity);

public sealed record ImportedEvidenceArtifact(
    IReadOnlyList<ImportedEvidenceFile> Files,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "release.imported-evidence";
}

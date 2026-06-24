using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

public sealed class ReleaseIntegrityAnalyzer : IRepositoryAnalyzer
{
    public string Id => "release.integrity";

    public string DisplayName => "Release Integrity Correlation";

    public AnalysisCategory Category => AnalysisCategory.Releases;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [ImportedEvidenceArtifact.ArtifactKey, DependencyInventoryArtifact.ArtifactKey];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-EVI010", "SBOM does not cover direct dependency inventory",
            AnalysisCategory.Releases, Severity.Medium, Confidence.Medium,
            "The imported SBOM appears incomplete relative to detected direct dependency inventory.",
            "Regenerate the SBOM from the current build graph to include all direct dependencies."),
        new("TRUST-EVI011", "Provenance subject does not contain a digest",
            AnalysisCategory.Releases, Severity.Medium, Confidence.High,
            "A provenance subject does not include a SHA-256 or SHA-512 digest.",
            "Ensure provenance generation includes cryptographic digests for all subjects."),
        new("TRUST-EVI012", "Provenance repository identity differs from target",
            AnalysisCategory.Releases, Severity.Medium, Confidence.Medium,
            "Provenance metadata references a different repository than the scanned target.",
            "Ensure provenance was generated for the current repository."),
        new("TRUST-EVI013", "Evidence contains conflicting component identities",
            AnalysisCategory.Releases, Severity.Low, Confidence.High,
            "Imported evidence contains duplicate component identities with conflicting versions.",
            "Review and reconcile conflicting component versions in imported evidence.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<ImportedEvidenceArtifact>(ImportedEvidenceArtifact.ArtifactKey, out var evidence) || evidence is null)
        {
            return Task.FromResult(new AnalyzerResult(ModuleStatus.Completed, [],
                null, null, ["Imported evidence artifact was not available; release integrity checks were skipped."]));
        }

        var findings = new List<Finding>();

        var hasDependencyInventory = context.TryGetArtifact<DependencyInventoryArtifact>(
            DependencyInventoryArtifact.ArtifactKey, out var inventory);

        // EVI010: SBOM coverage
        var sbomFiles = evidence.Files
            .Where(f => f.Kind is ImportedEvidenceKind.CycloneDx or ImportedEvidenceKind.Spdx)
            .ToArray();

        if (sbomFiles.Length > 0 && hasDependencyInventory && inventory is not null)
        {
            var directDeps = inventory.Packages
                .Where(p => p.IsDirect && !string.IsNullOrWhiteSpace(p.Name))
                .ToArray();

            if (directDeps.Length >= 10)
            {
                var sbomPurls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var f in sbomFiles)
                {
                    foreach (var c in f.Components)
                    {
                        if (!string.IsNullOrWhiteSpace(c.PackageUrl))
                        {
                            sbomPurls.Add(NormalizePurlForComparison(c.PackageUrl));
                        }
                    }
                }

                if (sbomPurls.Count > 0)
                {
                    var correlatableDeps = directDeps
                        .Where(d => !string.IsNullOrWhiteSpace(d.Name))
                        .ToArray();

                    var covered = correlatableDeps.Count(d =>
                        sbomPurls.Any(purl =>
                            purl.Contains(NormalizeNameForComparison(d.Name), StringComparison.OrdinalIgnoreCase)));

                    var coverage = (double)covered / correlatableDeps.Length;
                    if (coverage < 0.70)
                    {
                        findings.Add(new Finding(
                            "TRUST-EVI010",
                            "SBOM does not cover direct dependency inventory",
                            AnalysisCategory.Releases,
                            Severity.Medium,
                            Confidence.Medium,
                            $"The imported SBOM appears incomplete: approximately {covered} of {correlatableDeps.Length} direct dependencies are represented.",
                            [new Evidence("sbom-coverage", $"SBOM covers approximately {coverage:P0} of direct dependency inventory.")],
                            new Recommendation("Regenerate the SBOM from the current build graph to include all direct dependencies."),
                            IdentityKey: "evi010|scan"));
                    }
                }
            }
        }

        // EVI011: Provenance subject without digest
        foreach (var file in evidence.Files.Where(f => f.Kind is ImportedEvidenceKind.InToto or ImportedEvidenceKind.SlsaProvenance))
        {
            foreach (var subject in file.Subjects)
            {
                var hasDigest = subject.Digests.ContainsKey("sha256") || subject.Digests.ContainsKey("sha512");
                if (!hasDigest && !string.IsNullOrWhiteSpace(subject.Name))
                {
                    findings.Add(new Finding(
                        "TRUST-EVI011",
                        "Provenance subject does not contain a digest",
                        AnalysisCategory.Releases,
                        Severity.Medium,
                        Confidence.High,
                        $"Provenance subject `{subject.Name}` does not include a SHA-256 or SHA-512 digest.",
                        [new Evidence("provenance-digest", $"Subject `{subject.Name}` has no sha256 or sha512 digest.", file.FilePath)],
                        new Recommendation("Ensure provenance generation includes cryptographic digests for all subjects."),
                        IdentityKey: $"evi011|{file.FilePath}|{subject.Name}".ToLowerInvariant()));
                }
            }
        }

        // EVI012: Provenance repository mismatch
        foreach (var file in evidence.Files.Where(f => f.Kind is ImportedEvidenceKind.InToto or ImportedEvidenceKind.SlsaProvenance))
        {
            if (!string.IsNullOrWhiteSpace(file.RepositoryIdentity))
            {
                var normalizedTarget = NormalizeTarget(context.Target);
                var normalizedEvidence = NormalizeTarget(file.RepositoryIdentity);
                if (!string.IsNullOrWhiteSpace(normalizedTarget) &&
                    !string.IsNullOrWhiteSpace(normalizedEvidence) &&
                    !normalizedTarget.Equals(normalizedEvidence, StringComparison.OrdinalIgnoreCase) &&
                    !normalizedTarget.EndsWith("/" + normalizedEvidence, StringComparison.OrdinalIgnoreCase) &&
                    !normalizedEvidence.EndsWith("/" + normalizedTarget, StringComparison.OrdinalIgnoreCase))
                {
                    // Skip if EVI009 already exists for this
                    var existingEvi009 = context.Artifacts.ContainsKey("evi009-checked");
                    findings.Add(new Finding(
                        "TRUST-EVI012",
                        "Provenance repository identity differs from target",
                        AnalysisCategory.Releases,
                        Severity.Medium,
                        Confidence.Medium,
                        $"Provenance metadata references `{file.RepositoryIdentity}` which differs from scanned target.",
                        [new Evidence("provenance-repo", $"Provenance repository: {file.RepositoryIdentity}, target: {normalizedTarget}", file.FilePath)],
                        new Recommendation("Ensure provenance was generated for the current repository."),
                        IdentityKey: $"evi012|{file.FilePath}".ToLowerInvariant()));
                }
            }
        }

        // EVI013: Conflicting component identities
        foreach (var file in sbomFiles)
        {
            var componentsByPurl = new Dictionary<string, List<ImportedSbomComponent>>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in file.Components)
            {
                if (string.IsNullOrWhiteSpace(c.PackageUrl)) continue;
                var purl = NormalizePurlForComparison(c.PackageUrl);
                if (!componentsByPurl.TryGetValue(purl, out var list))
                {
                    list = [];
                    componentsByPurl[purl] = list;
                }
                list.Add(c);
            }

            foreach (var (purl, comps) in componentsByPurl)
            {
                var versions = comps
                    .Select(c => c.Version)
                    .Where(v => !string.IsNullOrWhiteSpace(v))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                if (versions.Length >= 2)
                {
                    findings.Add(new Finding(
                        "TRUST-EVI013",
                        "Evidence contains conflicting component identities",
                        AnalysisCategory.Releases,
                        Severity.Low,
                        Confidence.High,
                        $"Imported evidence contains conflicting versions for `{purl}`: {string.Join(", ", versions)}",
                        [new Evidence("sbom-conflict", $"Component `{purl}` appears with versions: {string.Join(", ", versions)}", file.FilePath)],
                        new Recommendation("Review and reconcile conflicting component versions in imported evidence."),
                        IdentityKey: $"evi013|{file.FilePath}|{purl}".ToLowerInvariant()));
                }
            }
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["release.integrity.sbom.file.count"] = sbomFiles.Length.ToString(),
            ["release.integrity.finding.count"] = findings.Count.ToString()
        };

        return Task.FromResult(AnalyzerResult.Completed(findings, metrics: metrics));
    }

    private static string NormalizePurlForComparison(string purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return "";
        var normalized = purl.Trim();
        // Strip qualifiers and subpath for identity comparison
        var qIndex = normalized.IndexOf('?');
        var hashIndex = normalized.IndexOf('#');
        if (qIndex >= 0) normalized = normalized[..qIndex];
        if (hashIndex >= 0) normalized = normalized[..hashIndex];
        return normalized.ToLowerInvariant();
    }

    private static string NormalizeNameForComparison(string name)
    {
        return (name ?? "").Trim().ToLowerInvariant();
    }

    private static string NormalizeTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return "";
        return target.Trim().TrimEnd('/').ToLowerInvariant();
    }
}

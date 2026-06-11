using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

public sealed class EvidenceImportAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] SbomFilePatterns = ["cyclonedx.json", "spdx.json", "bom.json", "sbom.json", "sbom.spdx.json"];
    private static readonly string[] ProvenanceFilePatterns = ["provenance.json", "attestation.json", "*.intoto.jsonl", "slsa.json"];

    public string Id => "evidence-import";

    public string DisplayName => "Evidence Import";

    public AnalysisCategory Category => AnalysisCategory.Releases;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(5);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-EVI001", "SBOM evidence found in repository", AnalysisCategory.Releases, Severity.Low, Confidence.High,
            "An SBOM file was found in the repository.", "SBOMs help track dependencies. Ensure the SBOM is up-to-date and covers all components."),
        new("TRUST-EVI002", "Dependency inventory may differ from SBOM", AnalysisCategory.Releases, Severity.Low, Confidence.Low,
            "An SBOM was found but cross-referencing with dependency inventory is not yet implemented.", "Manually verify SBOM completeness against known dependencies."),
        new("TRUST-EVI003", "Provenance evidence found in repository", AnalysisCategory.Releases, Severity.Low, Confidence.High,
            "A provenance or attestation file was found.", "Provenance evidence helps verify build integrity. Ensure it covers all release artifacts."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var hasSbom = false;

        foreach (var pattern in SbomFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
                findings.Add(new Finding("TRUST-EVI001", "SBOM evidence found in repository",
                    AnalysisCategory.Releases, Severity.Low, Confidence.High,
                    $"SBOM file '{Path.GetFileName(file)}' found.",
                    [new Evidence("sbom", $"SBOM file '{Path.GetFileName(file)}' detected.", relativePath)],
                    new Recommendation("SBOMs help track dependencies. Ensure the SBOM is up-to-date and covers all components.")));
                hasSbom = true;
            }
        }

        if (hasSbom)
        {
            findings.Add(new Finding("TRUST-EVI002", "Dependency inventory may differ from SBOM",
                AnalysisCategory.Releases, Severity.Low, Confidence.Low,
                "SBOM found. Automated cross-reference with dependency inventory is not yet implemented.",
                [new Evidence("sbom-cross-ref", "Manual review of SBOM completeness is recommended.", null)],
                new Recommendation("Manually verify SBOM completeness against known dependencies.")));
        }

        foreach (var pattern in ProvenanceFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
                findings.Add(new Finding("TRUST-EVI003", "Provenance evidence found in repository",
                    AnalysisCategory.Releases, Severity.Low, Confidence.High,
                    $"Provenance file '{Path.GetFileName(file)}' found.",
                    [new Evidence("provenance", $"Provenance file '{Path.GetFileName(file)}' detected.", relativePath)],
                    new Recommendation("Provenance evidence helps verify build integrity. Ensure it covers all release artifacts.")));
            }
        }

        return AnalyzerResult.Completed(findings);
    }
}

using System.Text.Json;
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
        new("TRUST-EVI001", "SBOM evidence found in repository", AnalysisCategory.Releases, Severity.Info, Confidence.High,
            "An SBOM file was found in the repository.", "SBOMs help track dependencies. Ensure the SBOM is up-to-date and covers all components."),
        new("TRUST-EVI003", "Provenance evidence found in repository", AnalysisCategory.Releases, Severity.Info, Confidence.High,
            "A provenance or attestation file was found.", "Provenance evidence helps verify build integrity. Ensure it covers all release artifacts."),
        new("TRUST-EVI004", "SBOM evidence file is not parseable", AnalysisCategory.Releases, Severity.Medium, Confidence.High,
            "An SBOM JSON file could not be parsed as JSON.", "Ensure SBOM files are valid JSON. Corrupt evidence cannot be trusted."),
        new("TRUST-EVI005", "SBOM evidence appears empty", AnalysisCategory.Releases, Severity.Low, Confidence.Medium,
            "An SBOM file is valid JSON but contains no components or packages.", "Regenerate the SBOM to include all components."),
        new("TRUST-EVI006", "Provenance evidence file is not parseable", AnalysisCategory.Releases, Severity.Medium, Confidence.High,
            "A provenance JSON or JSONL file could not be parsed.", "Ensure provenance files are valid JSON. Corrupt evidence cannot be trusted."),
        new("TRUST-EVI007", "SBOM appears potentially incomplete", AnalysisCategory.Releases, Severity.Low, Confidence.Medium,
            "An SBOM contains very few components suggesting it may be incomplete.", "Regenerate the SBOM from the current build graph."),
        new("TRUST-EVI008", "SBOM package URL is malformed", AnalysisCategory.Releases, Severity.Low, Confidence.High,
            "A purl identifier in an SBOM does not follow the pkg: scheme.", "Fix malformed package URLs in the SBOM."),
        new("TRUST-EVI009", "Evidence metadata target differs from scanned repository", AnalysisCategory.Releases, Severity.Medium, Confidence.Medium,
            "Evidence metadata references a different repository target.", "Ensure evidence was generated for the current repository."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var pattern in SbomFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

                findings.Add(new Finding("TRUST-EVI001", "SBOM evidence found in repository",
                    AnalysisCategory.Releases, Severity.Info, Confidence.High,
                    $"SBOM file '{Path.GetFileName(file)}' found.",
                    [new Evidence("sbom", $"SBOM file '{Path.GetFileName(file)}' detected.", relativePath)],
                    new Recommendation("SBOMs help track dependencies. Ensure the SBOM is up-to-date and covers all components.")));

                // Validate SBOM parseability
                if (file.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    ValidateSbomJson(file, relativePath, findings, cancellationToken);
                }
            }
        }

        foreach (var pattern in ProvenanceFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

                findings.Add(new Finding("TRUST-EVI003", "Provenance evidence found in repository",
                    AnalysisCategory.Releases, Severity.Info, Confidence.High,
                    $"Provenance file '{Path.GetFileName(file)}' found.",
                    [new Evidence("provenance", $"Provenance file '{Path.GetFileName(file)}' detected.", relativePath)],
                    new Recommendation("Provenance evidence helps verify build integrity. Ensure it covers all release artifacts.")));

                // Validate provenance parseability
                ValidateProvenance(file, relativePath, findings, cancellationToken);
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void ValidateSbomJson(string file, string relativePath, List<Finding> findings, CancellationToken ct)
    {
        if (!RepositoryFileSystem.CanReadAsText(file))
            return;

        ct.ThrowIfCancellationRequested();

        try
        {
            var json = File.ReadAllText(file);
            ct.ThrowIfCancellationRequested();

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Check for empty components/packages
            if (root.TryGetProperty("components", out var components))
            {
                var count = components.GetArrayLength();
                if (count == 0)
                {
                    findings.Add(CreateEviFinding("TRUST-EVI005", "SBOM evidence appears empty",
                        Severity.Low, relativePath, "SBOM has an empty 'components' array.", Confidence.Medium));
                }
                else if (count < 5)
                {
                    findings.Add(CreateEviFinding("TRUST-EVI007", "SBOM appears potentially incomplete",
                        Severity.Low, relativePath, $"SBOM has only {count} components.", Confidence.Medium));
                }

                // EVI008: check purl format
                foreach (var c in components.EnumerateArray())
                {
                    if (c.TryGetProperty("purl", out var purl))
                    {
                        var p = purl.GetString() ?? "";
                        if (p.StartsWith("pkg:") && !p.Contains('/'))
                        {
                            findings.Add(CreateEviFinding("TRUST-EVI008", "Malformed purl",
                                Severity.Low, relativePath, $"Purl '{p}' is malformed."));
                            break;
                        }
                    }
                }
            }
            else if (root.TryGetProperty("packages", out var packages) && packages.GetArrayLength() == 0)
            {
                findings.Add(CreateEviFinding("TRUST-EVI005", "SBOM evidence appears empty",
                    Severity.Low, relativePath, "SBOM has an empty 'packages' array.", Confidence.Medium));
            }

            // EVI009: check metadata target
            if (root.TryGetProperty("metadata", out var metadata) &&
                metadata.TryGetProperty("component", out var component) &&
                component.TryGetProperty("name", out var name))
            {
                var n = name.GetString() ?? "";
                if (n.Contains('/') && !relativePath.Contains(n.Split('/').Last(), StringComparison.OrdinalIgnoreCase))
                {
                    // Target name differs from scanned path - heuristic
                    findings.Add(CreateEviFinding("TRUST-EVI009", "Evidence target mismatch",
                        Severity.Medium, relativePath, $"SBOM metadata references '{n}' which may differ from scanned repo.", Confidence.Medium));
                }
            }
        }
        catch (JsonException)
        {
            findings.Add(CreateEviFinding("TRUST-EVI004", "SBOM evidence file is not parseable",
                Severity.Medium, relativePath, "SBOM JSON file is not valid JSON."));
        }
        catch (IOException)
        {
            // Skip unreadable files
        }
    }

    private static void ValidateProvenance(string file, string relativePath, List<Finding> findings, CancellationToken ct)
    {
        if (!RepositoryFileSystem.CanReadAsText(file))
            return;

        ct.ThrowIfCancellationRequested();

        try
        {
            var content = File.ReadAllText(file);
            ct.ThrowIfCancellationRequested();

            if (file.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
            {
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed))
                        continue;

                    try
                    {
                        using var doc = JsonDocument.Parse(trimmed);
                    }
                    catch (JsonException)
                    {
                        findings.Add(CreateEviFinding("TRUST-EVI006", "Provenance evidence file is not parseable",
                            Severity.Medium, relativePath, "A line in the provenance JSONL file is not valid JSON."));
                        return; // Report once per file
                    }
                }
            }
            else if (file.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(content);
            }
        }
        catch (JsonException)
        {
            findings.Add(CreateEviFinding("TRUST-EVI006", "Provenance evidence file is not parseable",
                Severity.Medium, relativePath, "Provenance JSON file is not valid JSON."));
        }
        catch (IOException)
        {
            // Skip unreadable files
        }
    }

    private static Finding CreateEviFinding(string ruleId, string title, Severity severity, string filePath, string evidence, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.Releases, severity, confidence, title,
            [new Evidence("evidence", evidence, filePath)],
            new Recommendation("Review the evidence file and ensure it is valid and complete."));
    }
}

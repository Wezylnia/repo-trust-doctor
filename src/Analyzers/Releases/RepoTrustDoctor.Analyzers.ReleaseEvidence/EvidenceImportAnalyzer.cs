using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

public sealed class EvidenceImportAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] SbomFilePatterns = ["cyclonedx.json", "spdx.json", "bom.json", "sbom.json", "sbom.spdx.json", "*.cdx.json", "*.spdx.json"];
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
        var processedSbomFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in SbomFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!processedSbomFiles.Add(Path.GetFullPath(file)))
                {
                    continue;
                }

                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

                if (file.EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
                    ValidateSbomJson(file, relativePath, context, findings, cancellationToken))
                {
                    findings.Add(new Finding("TRUST-EVI001", "SBOM evidence found in repository",
                        AnalysisCategory.Releases, Severity.Info, Confidence.High,
                        $"SBOM file '{Path.GetFileName(file)}' found.",
                        [new Evidence("sbom", $"Recognized SBOM file '{Path.GetFileName(file)}' detected.", relativePath)],
                        new Recommendation("SBOMs help track dependencies. Ensure the SBOM is up-to-date and covers all components.")));
                }
            }
        }

        foreach (var pattern in ProvenanceFilePatterns)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');

                if (ValidateProvenance(file, relativePath, findings, cancellationToken))
                {
                    findings.Add(new Finding("TRUST-EVI003", "Provenance evidence found in repository",
                        AnalysisCategory.Releases, Severity.Info, Confidence.High,
                        $"Provenance file '{Path.GetFileName(file)}' found.",
                        [new Evidence("provenance", $"Parseable provenance file '{Path.GetFileName(file)}' detected.", relativePath)],
                        new Recommendation("Provenance evidence helps verify build integrity. Ensure it covers all release artifacts.")));
                }
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static bool ValidateSbomJson(string file, string relativePath, AnalysisContext context, List<Finding> findings, CancellationToken ct)
    {
        if (!RepositoryFileSystem.CanReadAsText(file))
            return false;

        ct.ThrowIfCancellationRequested();

        try
        {
            var json = File.ReadAllText(file);
            ct.ThrowIfCancellationRequested();

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!IsRecognizedSbom(root, out var componentArray, out var packageArray))
            {
                findings.Add(CreateEviFinding("TRUST-EVI004", "SBOM evidence file is not parseable",
                    Severity.Medium, relativePath, "SBOM JSON file does not match recognized CycloneDX or SPDX structure."));
                return false;
            }

            if (componentArray.ValueKind == JsonValueKind.Array)
            {
                var count = componentArray.GetArrayLength();
                if (count == 0)
                {
                    findings.Add(CreateEviFinding("TRUST-EVI005", "SBOM evidence appears empty",
                        Severity.Low, relativePath, "SBOM has an empty 'components' array.", Confidence.Medium));
                }

                var directDependencyCount = GetDirectDependencyCount(context);
                if (count > 0 && directDependencyCount >= 20 && count < Math.Ceiling(directDependencyCount * 0.25))
                {
                    findings.Add(CreateEviFinding("TRUST-EVI007", "SBOM appears potentially incomplete",
                        Severity.Low, relativePath, $"SBOM has {count} components for {directDependencyCount} direct dependencies.", Confidence.Medium));
                }

                ValidateComponentPackageUrls(componentArray, relativePath, findings);
            }

            if (packageArray.ValueKind == JsonValueKind.Array &&
                packageArray.GetArrayLength() == 0)
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
                if (n.Contains('/') && !TargetMatches(context, n))
                {
                    findings.Add(CreateEviFinding("TRUST-EVI009", "Evidence target mismatch",
                        Severity.Medium, relativePath, $"SBOM metadata references '{n}' which may differ from scanned repo.", Confidence.Medium));
                }
            }

            return true;
        }
        catch (JsonException)
        {
            findings.Add(CreateEviFinding("TRUST-EVI004", "SBOM evidence file is not parseable",
                Severity.Medium, relativePath, "SBOM JSON file is not valid JSON."));
            return false;
        }
        catch (IOException)
        {
            // Skip unreadable files
            return false;
        }
    }

    private static bool IsRecognizedSbom(JsonElement root, out JsonElement components, out JsonElement packages)
    {
        components = default;
        packages = default;
        var isCycloneDx = root.TryGetProperty("bomFormat", out var bomFormat) &&
            bomFormat.ValueKind == JsonValueKind.String &&
            string.Equals(bomFormat.GetString(), "CycloneDX", StringComparison.OrdinalIgnoreCase);
        if (isCycloneDx &&
            root.TryGetProperty("components", out components) &&
            components.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        var isSpdx = root.TryGetProperty("spdxVersion", out var spdxVersion) &&
            spdxVersion.ValueKind == JsonValueKind.String &&
            (spdxVersion.GetString() ?? string.Empty).StartsWith("SPDX-", StringComparison.OrdinalIgnoreCase);
        if (isSpdx &&
            root.TryGetProperty("packages", out packages) &&
            packages.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        return false;
    }

    private static void ValidateComponentPackageUrls(JsonElement components, string relativePath, List<Finding> findings)
    {
        foreach (var sbomComponent in components.EnumerateArray())
        {
            if (sbomComponent.ValueKind == JsonValueKind.Object &&
                sbomComponent.TryGetProperty("purl", out var purl) &&
                purl.ValueKind == JsonValueKind.String)
            {
                var value = purl.GetString() ?? "";
                if (!IsValidPackageUrl(value))
                {
                    findings.Add(CreateEviFinding("TRUST-EVI008", "Malformed purl",
                        Severity.Low, relativePath, $"Purl '{value}' is malformed."));
                    break;
                }
            }
        }
    }

    private static int GetDirectDependencyCount(AnalysisContext context)
    {
        if (!context.TryGetArtifact<DependencyInventoryArtifact>(DependencyInventoryArtifact.ArtifactKey, out var inventory) || inventory is null)
            return 0;

        return inventory.Packages.Count(package => package.IsDirect);
    }

    private static bool IsValidPackageUrl(string value)
    {
        if (!value.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
            return false;

        var body = value["pkg:".Length..];
        var suffixStart = body.IndexOfAny(['?', '#']);
        if (suffixStart >= 0)
            body = body[..suffixStart];

        var slashIndex = body.IndexOf('/');
        if (slashIndex <= 0 || slashIndex == body.Length - 1)
            return false;

        var packageType = body[..slashIndex];
        var packageName = body[(slashIndex + 1)..];
        return packageType.All(IsPackageUrlTypeCharacter) &&
               packageName.Length > 0 &&
               !packageName.Any(char.IsWhiteSpace);
    }

    private static bool IsPackageUrlTypeCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) ||
        value is '.' or '+' or '-';

    private static bool TargetMatches(AnalysisContext context, string evidenceTarget)
    {
        var normalizedEvidence = NormalizeRepositoryIdentity(evidenceTarget);
        if (string.IsNullOrWhiteSpace(normalizedEvidence))
            return true;

        var normalizedTarget = NormalizeRepositoryIdentity(context.Target);
        if (string.IsNullOrWhiteSpace(normalizedTarget))
            normalizedTarget = NormalizeRepositoryIdentity(new DirectoryInfo(context.RepositoryPath).Name);

        if (string.IsNullOrWhiteSpace(normalizedTarget))
            return true;

        return normalizedTarget.Equals(normalizedEvidence, StringComparison.OrdinalIgnoreCase) ||
               normalizedTarget.EndsWith('/' + normalizedEvidence, StringComparison.OrdinalIgnoreCase) ||
               normalizedEvidence.EndsWith('/' + normalizedTarget, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRepositoryIdentity(string value)
    {
        var normalized = value.Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(normalized))
            return "";

        if (normalized.StartsWith("git@github.com:", StringComparison.OrdinalIgnoreCase))
            normalized = normalized["git@github.com:".Length..];
        else if (Uri.TryCreate(normalized, UriKind.Absolute, out var uri))
            normalized = uri.Host.Contains("github.com", StringComparison.OrdinalIgnoreCase)
                ? uri.AbsolutePath.Trim('/')
                : normalized;

        if (normalized.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[..^4];

        return normalized.Trim('/').ToLowerInvariant();
    }

    private static bool ValidateProvenance(string file, string relativePath, List<Finding> findings, CancellationToken ct)
    {
        if (!RepositoryFileSystem.CanReadAsText(file))
            return false;

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
                        return false;
                    }
                }

                return true;
            }
            else if (file.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(content);
                return true;
            }
        }
        catch (JsonException)
        {
            findings.Add(CreateEviFinding("TRUST-EVI006", "Provenance evidence file is not parseable",
                Severity.Medium, relativePath, "Provenance JSON file is not valid JSON."));
            return false;
        }
        catch (IOException)
        {
            // Skip unreadable files
            return false;
        }

        return false;
    }

    private static Finding CreateEviFinding(string ruleId, string title, Severity severity, string filePath, string evidence, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.Releases, severity, confidence, title,
            [new Evidence("evidence", evidence, filePath)],
            new Recommendation("Review the evidence file and ensure it is valid and complete."));
    }
}

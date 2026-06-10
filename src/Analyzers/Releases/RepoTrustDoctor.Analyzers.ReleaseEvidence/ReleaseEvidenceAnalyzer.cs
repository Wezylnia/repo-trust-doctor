using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

public sealed partial class ReleaseEvidenceAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] ArtifactExtensions = [".zip", ".tar", ".gz", ".tgz", ".nupkg", ".whl", ".exe", ".dll"];
    private static readonly string[] ArtifactRoots = ["dist", "release", "releases", "artifacts"];

    public string Id => "release-evidence";
    public string DisplayName => "Release Evidence";
    public AnalysisCategory Category => AnalysisCategory.Releases;
    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;
    public IReadOnlyCollection<string> DependsOn => [];
    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;
    public TimeSpan Timeout => TimeSpan.FromSeconds(10);
    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-REL001", "Changelog does not mention detected package version", AnalysisCategory.Releases, Severity.Low, Confidence.Medium, "A package version was detected but the changelog does not mention it.", "Add release notes for the package version in CHANGELOG.md."),
        new("TRUST-REL002", "Release artifact lacks checksum evidence", AnalysisCategory.Releases, Severity.Medium, Confidence.Medium, "A release artifact exists without a nearby checksum file.", "Publish SHA-256 or SHA-512 checksums next to release artifacts."),
        new("TRUST-REL003", "Release artifact lacks SBOM or provenance evidence", AnalysisCategory.Releases, Severity.Low, Confidence.Medium, "A release artifact exists without nearby SBOM, provenance, or attestation evidence.", "Publish SBOM or provenance/attestation evidence for release artifacts."),
        new("TRUST-REL004", "Package version does not match latest changelog version", AnalysisCategory.Releases, Severity.Medium, Confidence.Medium, "Detected package version differs from the latest version heading in the changelog.", "Keep package version metadata and release notes aligned."),
        new("TRUST-REL005", "Release workflow lacks integrity evidence steps", AnalysisCategory.Releases, Severity.Medium, Confidence.Medium, "A release workflow appears to publish artifacts without checksum, SBOM, provenance, or attestation steps.", "Add checksum, SBOM, provenance, or attestation generation to release workflows.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var changelog = FindChangelog(context.RepositoryPath);
        var changelogText = changelog is not null && RepositoryFileSystem.CanReadAsText(changelog)
            ? File.ReadAllText(changelog)
            : null;
        var changelogVersion = changelogText is null ? null : ReadLatestChangelogVersion(changelogText);

        foreach (var packageVersion in ReadPackageVersions(context))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.IsNullOrWhiteSpace(changelogText) &&
                !changelogText.Contains(packageVersion.Version, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(CreateFinding("TRUST-REL001", "Changelog does not mention detected package version", Severity.Low, Confidence.Medium, $"Package version `{packageVersion.Version}` is not mentioned in the changelog.", "release-version", $"Version `{packageVersion.Version}` detected in `{packageVersion.FilePath}`.", packageVersion.FilePath, "Add release notes for the package version in CHANGELOG.md."));
            }

            if (!string.IsNullOrWhiteSpace(changelogVersion) &&
                !string.Equals(NormalizeVersion(changelogVersion), NormalizeVersion(packageVersion.Version), StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(CreateFinding("TRUST-REL004", "Package version does not match latest changelog version", Severity.Medium, Confidence.Medium, $"Package version `{packageVersion.Version}` does not match changelog version `{changelogVersion}`.", "release-version", $"Package version `{packageVersion.Version}` differs from changelog `{changelogVersion}`.", packageVersion.FilePath, "Keep package version metadata and release notes aligned."));
            }
        }

        foreach (var artifact in EnumerateReleaseArtifacts(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context.RepositoryPath, artifact);
            var directory = Path.GetDirectoryName(artifact) ?? context.RepositoryPath;
            if (!Directory.EnumerateFiles(directory).Any(IsChecksumFile))
            {
                findings.Add(CreateFinding("TRUST-REL002", "Release artifact lacks checksum evidence", Severity.Medium, Confidence.Medium, "Release artifact exists without nearby checksum evidence.", "release-artifact", $"Artifact `{relativePath}` has no nearby checksum file.", relativePath, "Publish SHA-256 or SHA-512 checksums next to release artifacts."));
            }

            if (!Directory.EnumerateFiles(directory).Any(IsSupplyChainEvidenceFile))
            {
                findings.Add(CreateFinding("TRUST-REL003", "Release artifact lacks SBOM or provenance evidence", Severity.Low, Confidence.Medium, "Release artifact exists without nearby SBOM or provenance evidence.", "release-artifact", $"Artifact `{relativePath}` has no nearby SBOM/provenance evidence.", relativePath, "Publish SBOM or provenance/attestation evidence for release artifacts."));
            }
        }

        foreach (var workflow in EnumerateWorkflowFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(workflow))
            {
                continue;
            }

            var content = File.ReadAllText(workflow);
            if (ReleasePublishPattern().IsMatch(content) && !IntegrityEvidencePattern().IsMatch(content))
            {
                var relativePath = Relative(context.RepositoryPath, workflow);
                findings.Add(CreateFinding("TRUST-REL005", "Release workflow lacks integrity evidence steps", Severity.Medium, Confidence.Medium, "Release workflow appears to publish artifacts without integrity evidence steps.", "release-workflow", "Release publishing command found without checksum, SBOM, provenance, or attestation wording.", relativePath, "Add checksum, SBOM, provenance, or attestation generation to release workflows."));
            }
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static IEnumerable<PackageVersionEvidence> ReadPackageVersions(AnalysisContext context)
    {
        foreach (var packageJson in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json"))
        {
            var relativePath = Relative(context.RepositoryPath, packageJson);
            if (!RepositoryFileSystem.CanReadAsText(packageJson))
            {
                continue;
            }

            var version = TryReadPackageJsonVersion(packageJson);
            if (!string.IsNullOrWhiteSpace(version))
            {
                yield return new PackageVersionEvidence(relativePath, version);
            }
        }

        foreach (var project in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.csproj"))
        {
            var relativePath = Relative(context.RepositoryPath, project);
            if (!RepositoryFileSystem.CanReadAsText(project))
            {
                continue;
            }

            if (TryLoadXml(project, out var document))
            {
                var version = document.Descendants().FirstOrDefault(element => element.Name.LocalName is "Version" or "PackageVersion")?.Value;
                if (!string.IsNullOrWhiteSpace(version))
                {
                    yield return new PackageVersionEvidence(relativePath, version.Trim());
                }
            }
        }

        foreach (var pyproject in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pyproject.toml"))
        {
            var relativePath = Relative(context.RepositoryPath, pyproject);
            if (!RepositoryFileSystem.CanReadAsText(pyproject))
            {
                continue;
            }

            foreach (var line in File.ReadLines(pyproject))
            {
                var match = PyprojectVersionPattern().Match(line);
                if (match.Success)
                {
                    yield return new PackageVersionEvidence(relativePath, match.Groups["version"].Value);
                    break;
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateReleaseArtifacts(string repositoryPath)
    {
        foreach (var root in ArtifactRoots.Select(root => Path.Combine(repositoryPath, root)).Where(Directory.Exists))
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                         .Where(file => ArtifactExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)))
            {
                yield return file;
            }
        }
    }

    private static string? TryReadPackageJsonVersion(string packageJson)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(packageJson));
            if (document.RootElement.TryGetProperty("version", out var version) &&
                version.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(version.GetString()))
            {
                return version.GetString();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }

    private static IEnumerable<string> EnumerateWorkflowFiles(string repositoryPath)
    {
        var workflowRoot = Path.Combine(repositoryPath, ".github", "workflows");
        if (!Directory.Exists(workflowRoot))
        {
            return [];
        }

        return RepositoryFileSystem.EnumerateFiles(workflowRoot, "*.*", SearchOption.TopDirectoryOnly)
            .Where(file => file.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase));
    }

    private static string? FindChangelog(string repositoryPath)
    {
        foreach (var name in new[] { "CHANGELOG.md", "CHANGELOG", "HISTORY.md", "RELEASES.md" })
        {
            var path = Path.Combine(repositoryPath, name);
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    private static string? ReadLatestChangelogVersion(string content)
    {
        foreach (var line in content.Split('\n'))
        {
            var match = ChangelogHeadingPattern().Match(line.Trim());
            if (match.Success)
            {
                return match.Groups["version"].Value;
            }
        }

        return null;
    }

    private static bool TryLoadXml(string filePath, out XDocument document)
    {
        document = default!;
        try
        {
            using var stream = File.OpenRead(filePath);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            });
            document = XDocument.Load(reader);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsChecksumFile(string path)
    {
        var name = Path.GetFileName(path);
        return name.Contains("sha256", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("sha512", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("checksum", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".sig", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSupplyChainEvidenceFile(string path)
    {
        var name = Path.GetFileName(path);
        return name.Contains("sbom", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("provenance", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("attestation", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".intoto.jsonl", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeVersion(string version) => version.Trim().TrimStart('v');

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');

    private static Finding CreateFinding(string ruleId, string title, Severity severity, Confidence confidence, string message, string evidenceKind, string evidence, string filePath, string recommendation) =>
        new(ruleId, title, AnalysisCategory.Releases, severity, confidence, message, [new Evidence(evidenceKind, evidence, filePath)], new Recommendation(recommendation));

    private sealed record PackageVersionEvidence(string FilePath, string Version);

    [GeneratedRegex(@"^#+\s*\[?(?<version>v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\]?", RegexOptions.CultureInvariant)]
    private static partial Regex ChangelogHeadingPattern();

    [GeneratedRegex(@"^\s*version\s*=\s*[""'](?<version>[^""']+)[""']", RegexOptions.CultureInvariant)]
    private static partial Regex PyprojectVersionPattern();

    [GeneratedRegex(@"(?mi)\b(gh\s+release\s+(?:create|upload)|npm\s+publish|dotnet\s+nuget\s+push|nuget\s+push|twine\s+upload|docker\s+(?:push|buildx\s+build.+--push))\b")]
    private static partial Regex ReleasePublishPattern();

    [GeneratedRegex(@"(?mi)\b(sha256sum|sha512sum|Get-FileHash|checksum|sbom|syft|cyclonedx|provenance|attestation|cosign|slsa)\b")]
    private static partial Regex IntegrityEvidencePattern();
}

using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

public sealed partial class ReleaseEvidenceAnalyzer : IRepositoryAnalyzer
{
    private const int PackageVersionFindingLimit = 10;

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
        var changelogText = changelog is not null && TryReadText(changelog, out var text) ? text : null;
        var changelogVersion = changelogText is null ? null : ReleaseEvidenceParsing.ReadLatestChangelogVersion(changelogText);
        var packageVersions = ReadPackageVersions(context).ToArray();
        var releaseNotesResolver = new ReleaseNotesResolver(
            context.RepositoryPath,
            changelog,
            changelogText,
            changelogVersion);

        var packageVersionFindings = new List<Finding>();
        foreach (var packageVersion in packageVersions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var releaseNotes = releaseNotesResolver.Resolve(packageVersion);
            if (releaseNotes is null)
            {
                continue;
            }

            if (!releaseNotes.MentionsVersion)
            {
                packageVersionFindings.Add(CreateFinding("TRUST-REL001", "Changelog does not mention detected package version", Severity.Low, Confidence.Medium, $"Package version `{packageVersion.Version}` is not mentioned in the changelog.", "release-version", $"Version `{packageVersion.Version}` detected in `{packageVersion.FilePath}`.", packageVersion.FilePath, "Add release notes for the package version in CHANGELOG.md."));
            }

            if (!string.IsNullOrWhiteSpace(releaseNotes.LatestVersion) &&
                !string.Equals(NormalizeVersion(releaseNotes.LatestVersion), NormalizeVersion(packageVersion.Version), StringComparison.OrdinalIgnoreCase))
            {
                packageVersionFindings.Add(CreateFinding("TRUST-REL004", "Package version does not match latest changelog version", Severity.Medium, Confidence.Medium, $"Package version `{packageVersion.Version}` does not match changelog version `{releaseNotes.LatestVersion}`.", "release-version", $"Package version `{packageVersion.Version}` differs from changelog `{releaseNotes.LatestVersion}`.", packageVersion.FilePath, "Keep package version metadata and release notes aligned."));
            }
        }

        findings.AddRange(packageVersionFindings.Take(PackageVersionFindingLimit));

        foreach (var artifact in EnumerateReleaseArtifacts(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context.RepositoryPath, artifact);
            var directory = Path.GetDirectoryName(artifact) ?? context.RepositoryPath;
            if (!EnumerateDirectoryFiles(directory).Any(IsChecksumFile))
            {
                findings.Add(CreateFinding("TRUST-REL002", "Release artifact lacks checksum evidence", Severity.Medium, Confidence.Medium, "Release artifact exists without nearby checksum evidence.", "release-artifact", $"Artifact `{relativePath}` has no nearby checksum file.", relativePath, "Publish SHA-256 or SHA-512 checksums next to release artifacts."));
            }

            if (!EnumerateDirectoryFiles(directory).Any(IsSupplyChainEvidenceFile))
            {
                findings.Add(CreateFinding("TRUST-REL003", "Release artifact lacks SBOM or provenance evidence", Severity.Low, Confidence.Medium, "Release artifact exists without nearby SBOM or provenance evidence.", "release-artifact", $"Artifact `{relativePath}` has no nearby SBOM/provenance evidence.", relativePath, "Publish SBOM or provenance/attestation evidence for release artifacts."));
            }
        }

        foreach (var workflow in EnumerateWorkflowFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryReadText(workflow, out var content))
            {
                continue;
            }

            var executableContent = ReleaseEvidenceParsing.RemoveYamlComments(content);
            if (ReleasePublishPattern().IsMatch(executableContent) &&
                !IntegrityEvidencePattern().IsMatch(executableContent))
            {
                var relativePath = Relative(context.RepositoryPath, workflow);
                findings.Add(CreateFinding("TRUST-REL005", "Release workflow lacks integrity evidence steps", Severity.Medium, Confidence.Medium, "Release workflow appears to publish artifacts without integrity evidence steps.", "release-workflow", "Release publishing command found without checksum, SBOM, provenance, or attestation wording.", relativePath, "Add checksum, SBOM, provenance, or attestation generation to release workflows."));
            }
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static IEnumerable<ReleasePackageVersion> ReadPackageVersions(AnalysisContext context)
    {
        foreach (var packageJson in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json"))
        {
            var relativePath = Relative(context.RepositoryPath, packageJson);
            if (RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(relativePath))
            {
                continue;
            }

            var package = TryReadPackageJsonVersion(packageJson);
            if (package is not null && !package.IsPrivate)
            {
                yield return new ReleasePackageVersion(relativePath, package.Name, package.Version, "npm");
            }
        }

        foreach (var project in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.csproj"))
        {
            var relativePath = Relative(context.RepositoryPath, project);
            if (RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(relativePath))
            {
                continue;
            }

            if (!RepositoryFileSystem.CanReadAsText(project))
            {
                continue;
            }

            if (TryLoadXml(project, out var document))
            {
                var version = document.Descendants().FirstOrDefault(element => element.Name.LocalName is "Version" or "PackageVersion")?.Value;
                if (!string.IsNullOrWhiteSpace(version))
                {
                    var packageName = document.Descendants()
                        .FirstOrDefault(element => element.Name.LocalName is "PackageId" or "AssemblyName")
                        ?.Value
                        ?.Trim();
                    yield return new ReleasePackageVersion(
                        relativePath,
                        string.IsNullOrWhiteSpace(packageName)
                            ? Path.GetFileNameWithoutExtension(project)
                            : packageName,
                        version.Trim(),
                        "nuget");
                }
            }
        }

        foreach (var pyproject in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pyproject.toml"))
        {
            var relativePath = Relative(context.RepositoryPath, pyproject);
            if (RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(relativePath))
            {
                continue;
            }

            if (!TryReadText(pyproject, out var content))
            {
                continue;
            }

            var package = ReleaseEvidenceParsing.ReadPyprojectPackage(content);
            if (!string.IsNullOrWhiteSpace(package.Version))
            {
                yield return new ReleasePackageVersion(
                    relativePath,
                    package.Name ?? Path.GetFileName(Path.GetDirectoryName(pyproject)),
                    package.Version,
                    "pypi");
            }
        }
    }

    private static IEnumerable<string> EnumerateReleaseArtifacts(string repositoryPath)
    {
        var ignoredRootDirectories = ReadRootGitIgnoreDirectories(repositoryPath);
        foreach (var rootName in ArtifactRoots.Where(root => !ignoredRootDirectories.Contains(root)))
        {
            var root = Path.Combine(repositoryPath, rootName);
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (var file in RepositoryFileSystem.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                         .Where(file => ArtifactExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)))
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> EnumerateDirectoryFiles(string directory)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var file in files)
        {
            yield return file;
        }
    }

    private static NpmPackageVersion? TryReadPackageJsonVersion(string packageJson)
    {
        try
        {
            if (!TryReadText(packageJson, out var content))
            {
                return null;
            }

            using var document = JsonDocument.Parse(content);
            var name = document.RootElement.TryGetProperty("name", out var nameElement) &&
                       nameElement.ValueKind == JsonValueKind.String
                ? nameElement.GetString()
                : null;
            if (document.RootElement.TryGetProperty("version", out var version) &&
                version.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(version.GetString()))
            {
                var isPrivate = document.RootElement.TryGetProperty("private", out var privateElement) &&
                                privateElement.ValueKind == JsonValueKind.True;
                return new NpmPackageVersion(name, version.GetString()!, isPrivate);
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

    private static HashSet<string> ReadRootGitIgnoreDirectories(string repositoryPath)
    {
        var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var gitignore = Path.Combine(repositoryPath, ".gitignore");
        if (!TryReadText(gitignore, out var content))
        {
            return ignored;
        }

        foreach (var rawLine in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!') || line.Contains('*', StringComparison.Ordinal))
            {
                continue;
            }

            line = line.TrimStart('/').TrimEnd('/');
            if (line.Length == 0 || line.Contains('/') || line.Contains('\\'))
            {
                continue;
            }

            ignored.Add(line);
        }

        return ignored;
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
               name.Contains("checksum", StringComparison.OrdinalIgnoreCase);
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

    private static bool TryReadText(string path, out string content)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(path))
        {
            return false;
        }

        try
        {
            content = File.ReadAllText(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, Confidence confidence, string message, string evidenceKind, string evidence, string filePath, string recommendation) =>
        new(ruleId, title, AnalysisCategory.Releases, severity, confidence, message, [new Evidence(evidenceKind, evidence, filePath)], new Recommendation(recommendation));

    private sealed record NpmPackageVersion(string? Name, string Version, bool IsPrivate);

    [GeneratedRegex(@"(?mi)\b(gh\s+release\s+(?:create|upload)|npm\s+publish|dotnet\s+nuget\s+push|nuget\s+push|twine\s+upload|docker\s+(?:push|buildx\s+build.+--push))\b")]
    private static partial Regex ReleasePublishPattern();

    [GeneratedRegex(@"(?mi)\b(sha256sum|sha512sum|Get-FileHash|checksum|sbom|syft|cyclonedx|provenance|attestation|cosign|slsa)\b")]
    private static partial Regex IntegrityEvidencePattern();
}

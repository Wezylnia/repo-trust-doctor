using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

public sealed partial class DependencyInventoryAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] NpmLockfileNames = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
    private static readonly string[] PythonLockfileNames = ["Pipfile.lock", "poetry.lock", "uv.lock"];

    public string Id => "dependency-inventory";

    public string DisplayName => "Dependency Inventory";

    public AnalysisCategory Category => AnalysisCategory.Dependencies;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DEP001", "npm manifest exists without lockfile", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json file exists but no lockfile was found.", "Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository."),
        new("TRUST-DEP002", "NuGet project does not use lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A NuGet project exists but no packages.lock.json was found.", "Enable NuGet lock files and commit packages.lock.json to the repository."),
        new("TRUST-DEP003", "Python dependency manifest does not have a recognized lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A Python dependency manifest exists but no recognized lockfile was found.", "Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository."),
        new("TRUST-DEP004", "NuGet dependency uses a floating or unpinned version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A direct NuGet dependency is missing an exact pinned version or uses a floating/ranged version.", "Pin direct NuGet dependency versions or resolve them through Central Package Management."),
        new("TRUST-DEP005", "NuGet dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A direct NuGet dependency uses a prerelease version.", "Review whether the prerelease dependency is intentional before production use."),
        new("TRUST-DEP006", "npm dependency uses a range or unpinned version", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json dependency uses a range, tag, workspace reference, or otherwise non-exact version.", "Use exact dependency versions together with a committed lockfile for reproducible installs."),
        new("TRUST-DEP007", "npm dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A package.json dependency uses a prerelease version.", "Review prerelease dependencies and prefer stable versions where possible."),
        new("TRUST-DEP008", "npm install-time script requires manual review", AnalysisCategory.Dependencies, Severity.Medium, Confidence.Medium, "package.json defines an install-time script such as preinstall, install, or postinstall.", "Manually review install-time scripts because they run during package installation."),
        new("TRUST-DEP009", "Python requirement is unpinned", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A Python dependency is not pinned to an exact version.", "Pin Python requirements or use a lockfile-based package manager."),
        new("TRUST-DEP010", "Python dependency uses a prerelease version", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A Python dependency uses a prerelease version.", "Review whether the prerelease dependency is intentional before production use."),
        new("TRUST-DEP011", "npm dependency uses a direct remote source", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json dependency points directly at a Git or URL source instead of a registry version.", "Review direct remote dependency sources and prefer registry packages with pinned versions when possible."),
        new("TRUST-DEP012", "npm dependency uses a local file source", AnalysisCategory.Dependencies, Severity.Low, Confidence.High, "A package.json dependency points at a local file, link, workspace, or portal source.", "Review local dependency sources because they depend on repository layout and may bypass registry provenance."),
        new("TRUST-DEP013", "NuGet package source uses insecure transport", AnalysisCategory.Dependencies, Severity.High, Confidence.High, "NuGet.config defines an HTTP package source.", "Use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport."),
        new("TRUST-DEP014", "NuGet package source uses a local path", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "NuGet.config defines a local package source.", "Review local package sources because they can change package origin assumptions and may hide dependency confusion risk.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var warnings = new List<string>();
        var manifests = new List<DependencyManifestInfo>();
        var lockfiles = new List<DependencyLockfileInfo>();
        var packages = new List<DependencyPackageInfo>();
        var sources = new List<DependencyPackageSourceInfo>();

        AnalyzeNpm(context, findings, warnings, manifests, lockfiles, packages, cancellationToken);
        AnalyzeNuGet(context, findings, warnings, manifests, lockfiles, packages, sources, cancellationToken);
        AnalyzePython(context, findings, warnings, manifests, lockfiles, packages, cancellationToken);

        var metrics = BuildMetrics(manifests, lockfiles, packages, sources);
        var artifact = new DependencyInventoryArtifact(manifests, lockfiles, packages, sources, metrics);

        return Task.FromResult(AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, artifact)],
            metrics,
            warnings));
    }

    private static void AnalyzeNpm(
        AnalysisContext context,
        List<Finding> findings,
        List<string> warnings,
        List<DependencyManifestInfo> manifests,
        List<DependencyLockfileInfo> lockfiles,
        List<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        var packageJsons = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json").ToArray();
        foreach (var manifest in packageJsons)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context, manifest);
            var directory = Path.GetDirectoryName(manifest);
            if (directory is null)
            {
                continue;
            }

            var localLockfiles = NpmLockfileNames
                .Select(name => Path.Combine(directory, name))
                .Where(File.Exists)
                .ToArray();

            foreach (var lockfile in localLockfiles)
            {
                lockfiles.Add(new DependencyLockfileInfo(DependencyEcosystem.Npm, Relative(context, lockfile), Path.GetFileName(lockfile)));
            }

            if (localLockfiles.Length == 0)
            {
                findings.Add(new Finding(
                    "TRUST-DEP001",
                    "npm manifest exists without lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Medium,
                    Confidence.High,
                    "npm manifest exists without lockfile",
                    [new Evidence("package-manifest", "A package.json file exists but no lockfile was found.", relativePath)],
                    new Recommendation("Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository.")));
            }

            if (!TryReadText(manifest, out var json, warnings, relativePath))
            {
                manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Npm, relativePath, "package.json"));
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                var metadata = ReadNpmManifestMetadata(root);
                manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Npm, relativePath, "package.json", metadata));

                ReadNpmDependencySection(root, "dependencies", DependencyScope.Production, relativePath, localLockfiles, packages, findings);
                ReadNpmDependencySection(root, "devDependencies", DependencyScope.Development, relativePath, localLockfiles, packages, findings);
                ReadNpmDependencySection(root, "optionalDependencies", DependencyScope.Optional, relativePath, localLockfiles, packages, findings);
                ReadNpmDependencySection(root, "peerDependencies", DependencyScope.Peer, relativePath, localLockfiles, packages, findings);

                if (root.TryGetProperty("scripts", out var scripts) && scripts.ValueKind == JsonValueKind.Object)
                {
                    foreach (var scriptName in new[] { "preinstall", "install", "postinstall" })
                    {
                        if (scripts.TryGetProperty(scriptName, out var script) && script.ValueKind == JsonValueKind.String)
                        {
                            findings.Add(new Finding(
                                "TRUST-DEP008",
                                "npm install-time script requires manual review",
                                AnalysisCategory.Dependencies,
                                Severity.Medium,
                                Confidence.Medium,
                                $"package.json defines `{scriptName}`. Install-time scripts can execute during dependency installation.",
                                [new Evidence("npm-script", $"Install-time script `{scriptName}` is defined.", relativePath, Value: scriptName)],
                                new Recommendation("Review install-time scripts and avoid downloading or executing untrusted remote code.")));
                        }
                    }
                }
            }
            catch (JsonException ex)
            {
                warnings.Add($"Could not parse npm manifest '{relativePath}': {ex.Message}");
                manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Npm, relativePath, "package.json"));
            }
        }
    }

    private static void AnalyzeNuGet(
        AnalysisContext context,
        List<Finding> findings,
        List<string> warnings,
        List<DependencyManifestInfo> manifests,
        List<DependencyLockfileInfo> lockfiles,
        List<DependencyPackageInfo> packages,
        List<DependencyPackageSourceInfo> sources,
        CancellationToken cancellationToken)
    {
        var csprojs = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.csproj").ToArray();
        var centralVersions = ReadCentralPackageVersions(context, warnings);

        foreach (var lockfile in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "packages.lock.json"))
        {
            lockfiles.Add(new DependencyLockfileInfo(DependencyEcosystem.NuGet, Relative(context, lockfile), "packages.lock.json"));
        }

        foreach (var config in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "NuGet.config"))
        {
            ReadNuGetSources(context, config, warnings, findings, sources);
        }

        if (csprojs.Length > 0 && lockfiles.All(lockfile => lockfile.Ecosystem != DependencyEcosystem.NuGet))
        {
            var relativePath = Relative(context, csprojs[0]);
            findings.Add(new Finding(
                "TRUST-DEP002",
                "NuGet project does not use lockfile",
                AnalysisCategory.Dependencies,
                Severity.Low,
                Confidence.Medium,
                "NuGet project does not use lockfile",
                [new Evidence("package-manifest", "A NuGet project exists but no packages.lock.json was found.", relativePath)],
                new Recommendation("Enable NuGet lock files and restore locked mode, then commit packages.lock.json to the repository.")));
        }

        foreach (var project in csprojs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context, project);
            manifests.Add(new DependencyManifestInfo(DependencyEcosystem.NuGet, relativePath, ".csproj"));

            if (!TryLoadXml(project, warnings, relativePath, out var document))
            {
                continue;
            }

            foreach (var reference in document.Descendants().Where(element => element.Name.LocalName == "PackageReference"))
            {
                var name = ReadXmlAttribute(reference, "Include") ?? ReadXmlAttribute(reference, "Update");
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var version = ReadXmlAttribute(reference, "Version") ??
                              reference.Elements().FirstOrDefault(element => element.Name.LocalName == "Version")?.Value;

                if (string.IsNullOrWhiteSpace(version) && centralVersions.TryGetValue(NormalizePackageName(name), out var centralVersion))
                {
                    version = centralVersion;
                }

                var normalizedVersion = NormalizeVersion(version);
                var pinned = IsPinnedNuGetVersion(normalizedVersion);
                var prerelease = IsPrereleaseVersion(normalizedVersion);
                packages.Add(new DependencyPackageInfo(
                    DependencyEcosystem.NuGet,
                    name.Trim(),
                    normalizedVersion,
                    DependencyScope.Production,
                    relativePath,
                    null,
                    true,
                    pinned,
                    prerelease));

                if (!pinned)
                {
                    findings.Add(CreateDependencyFinding(
                        "TRUST-DEP004",
                        "NuGet dependency uses a floating or unpinned version",
                        Severity.Medium,
                        Confidence.High,
                        $"NuGet dependency `{name.Trim()}` is missing an exact pinned version.",
                        "nuget-package",
                        $"Package `{name.Trim()}` version is `{DisplayVersion(normalizedVersion)}`.",
                        relativePath,
                        "Pin direct NuGet dependency versions or resolve them through Central Package Management."));
                }

                if (prerelease)
                {
                    findings.Add(CreateDependencyFinding(
                        "TRUST-DEP005",
                        "NuGet dependency uses a prerelease version",
                        Severity.Low,
                        Confidence.High,
                        $"NuGet dependency `{name.Trim()}` uses prerelease version `{normalizedVersion}`.",
                        "nuget-package",
                        $"Package `{name.Trim()}` version is `{normalizedVersion}`.",
                        relativePath,
                        "Review whether the prerelease dependency is intentional before production use."));
                }
            }
        }

        if (centralVersions.Count > 0)
        {
            manifests.AddRange(RepositoryFileSystem
                .EnumerateFiles(context.RepositoryPath, "Directory.Packages.props")
                .Select(path => new DependencyManifestInfo(DependencyEcosystem.NuGet, Relative(context, path), "Directory.Packages.props")));
        }
    }

    private static void AnalyzePython(
        AnalysisContext context,
        List<Finding> findings,
        List<string> warnings,
        List<DependencyManifestInfo> manifests,
        List<DependencyLockfileInfo> lockfiles,
        List<DependencyPackageInfo> packages,
        CancellationToken cancellationToken)
    {
        foreach (var lockfile in PythonLockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            lockfiles.Add(new DependencyLockfileInfo(DependencyEcosystem.Python, Relative(context, lockfile), Path.GetFileName(lockfile)));
        }

        var pythonLockfileExists = lockfiles.Any(lockfile => lockfile.Ecosystem == DependencyEcosystem.Python);

        foreach (var requirements in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "requirements.txt"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context, requirements);
            manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "requirements.txt"));
            if (!pythonLockfileExists)
            {
                findings.Add(new Finding(
                    "TRUST-DEP003",
                    "Python dependency manifest does not have a recognized lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Low,
                    Confidence.Medium,
                    "Python dependency manifest does not have a recognized lockfile",
                    [new Evidence("package-manifest", "A requirements.txt exists but no recognized lockfile was found.", relativePath)],
                    new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
            }

            if (TryReadText(requirements, out var content, warnings, relativePath))
            {
                foreach (var package in ParseRequirements(content, relativePath))
                {
                    packages.Add(package);
                    AddPythonVersionFindings(package, findings);
                }
            }
        }

        foreach (var pyproject in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pyproject.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context, pyproject);
            manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "pyproject.toml"));
            if (!pythonLockfileExists)
            {
                findings.Add(new Finding(
                    "TRUST-DEP003",
                    "Python dependency manifest does not have a recognized lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Low,
                    Confidence.Medium,
                    "Python dependency manifest does not have a recognized lockfile",
                    [new Evidence("package-manifest", "A pyproject.toml exists but neither poetry.lock nor uv.lock was found.", relativePath)],
                    new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
            }

            if (TryReadText(pyproject, out var content, warnings, relativePath))
            {
                foreach (var package in ParsePyproject(content, relativePath))
                {
                    packages.Add(package);
                    AddPythonVersionFindings(package, findings);
                }
            }
        }

        foreach (var pipfile in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Pipfile"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Relative(context, pipfile);
            manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "Pipfile"));
            if (!lockfiles.Any(lockfile => lockfile.Kind.Equals("Pipfile.lock", StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new Finding(
                    "TRUST-DEP003",
                    "Python dependency manifest does not have a recognized lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Low,
                    Confidence.Medium,
                    "Python dependency manifest does not have a recognized lockfile",
                    [new Evidence("package-manifest", "A Pipfile exists but no Pipfile.lock was found.", relativePath)],
                    new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
            }

            if (TryReadText(pipfile, out var content, warnings, relativePath))
            {
                foreach (var package in ParsePipfile(content, relativePath))
                {
                    packages.Add(package);
                    AddPythonVersionFindings(package, findings);
                }
            }
        }
    }

    private static void ReadNpmDependencySection(
        JsonElement root,
        string sectionName,
        DependencyScope scope,
        string manifestPath,
        string[] localLockfiles,
        List<DependencyPackageInfo> packages,
        List<Finding> findings)
    {
        if (!root.TryGetProperty(sectionName, out var section) || section.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var dependency in section.EnumerateObject())
        {
            var version = dependency.Value.ValueKind == JsonValueKind.String ? dependency.Value.GetString() : null;
            var normalizedVersion = NormalizeVersion(version);
            var pinned = IsPinnedNpmVersion(normalizedVersion);
            var prerelease = IsPrereleaseVersion(normalizedVersion);
            var sourceKind = ClassifyNpmVersionSpec(normalizedVersion);
            packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Npm,
                dependency.Name,
                normalizedVersion,
                scope,
                manifestPath,
                localLockfiles.Length == 0 ? null : Path.GetFileName(localLockfiles[0]),
                true,
                pinned,
                prerelease,
                new Dictionary<string, string>
                {
                    ["section"] = sectionName,
                    ["sourceKind"] = sourceKind.Kind
                }));

            if (!pinned)
            {
                findings.Add(CreateDependencyFinding(
                    "TRUST-DEP006",
                    "npm dependency uses a range or unpinned version",
                    Severity.Medium,
                    Confidence.High,
                    $"npm dependency `{dependency.Name}` uses a non-exact version.",
                    "npm-package",
                    $"Package `{dependency.Name}` in `{sectionName}` uses version `{DisplayVersion(normalizedVersion)}`.",
                    manifestPath,
                    "Use exact dependency versions together with a committed lockfile for reproducible installs."));
            }

            if (prerelease)
            {
                findings.Add(CreateDependencyFinding(
                    "TRUST-DEP007",
                    "npm dependency uses a prerelease version",
                    Severity.Low,
                    Confidence.High,
                    $"npm dependency `{dependency.Name}` uses prerelease version `{normalizedVersion}`.",
                    "npm-package",
                    $"Package `{dependency.Name}` in `{sectionName}` uses version `{normalizedVersion}`.",
                    manifestPath,
                    "Review prerelease dependencies and prefer stable versions where possible."));
            }

            if (sourceKind.IsRemote)
            {
                findings.Add(CreateDependencyFinding(
                    "TRUST-DEP011",
                    "npm dependency uses a direct remote source",
                    Severity.Medium,
                    Confidence.High,
                    $"npm dependency `{dependency.Name}` points directly at a remote source.",
                    "npm-package",
                    $"Package `{dependency.Name}` in `{sectionName}` uses `{DisplayVersion(normalizedVersion)}`.",
                    manifestPath,
                    "Review direct remote dependency sources and prefer registry packages with pinned versions when possible."));
            }

            if (sourceKind.IsLocal)
            {
                findings.Add(CreateDependencyFinding(
                    "TRUST-DEP012",
                    "npm dependency uses a local file source",
                    Severity.Low,
                    Confidence.High,
                    $"npm dependency `{dependency.Name}` points at a local source.",
                    "npm-package",
                    $"Package `{dependency.Name}` in `{sectionName}` uses `{DisplayVersion(normalizedVersion)}`.",
                    manifestPath,
                    "Review local dependency sources because they depend on repository layout and may bypass registry provenance."));
            }
        }
    }

    private static IReadOnlyDictionary<string, string> ReadNpmManifestMetadata(JsonElement root)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("packageManager", out var packageManager) && packageManager.ValueKind == JsonValueKind.String)
        {
            metadata["packageManager"] = packageManager.GetString() ?? string.Empty;
        }

        if (root.TryGetProperty("engines", out var engines) && engines.ValueKind == JsonValueKind.Object)
        {
            foreach (var engine in engines.EnumerateObject())
            {
                if (engine.Value.ValueKind == JsonValueKind.String)
                {
                    metadata[$"engine.{engine.Name}"] = engine.Value.GetString() ?? string.Empty;
                }
            }
        }

        return metadata;
    }

    private static Dictionary<string, string> ReadCentralPackageVersions(AnalysisContext context, List<string> warnings)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var props in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Directory.Packages.props"))
        {
            var relativePath = Relative(context, props);
            if (!TryLoadXml(props, warnings, relativePath, out var document))
            {
                continue;
            }

            foreach (var packageVersion in document.Descendants().Where(element => element.Name.LocalName == "PackageVersion"))
            {
                var name = ReadXmlAttribute(packageVersion, "Include") ?? ReadXmlAttribute(packageVersion, "Update");
                var version = ReadXmlAttribute(packageVersion, "Version");
                if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(version))
                {
                    versions[NormalizePackageName(name)] = version.Trim();
                }
            }
        }

        return versions;
    }

    private static void ReadNuGetSources(
        AnalysisContext context,
        string configPath,
        List<string> warnings,
        List<Finding> findings,
        List<DependencyPackageSourceInfo> sources)
    {
        var relativePath = Relative(context, configPath);
        if (!TryLoadXml(configPath, warnings, relativePath, out var document))
        {
            return;
        }

        foreach (var source in document.Descendants().Where(element =>
            element.Name.LocalName == "add" &&
            element.Ancestors().Any(ancestor => ancestor.Name.LocalName == "packageSources")))
        {
            var name = ReadXmlAttribute(source, "key");
            var value = ReadXmlAttribute(source, "value");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(value))
            {
                var sourceText = value.Trim();
                var sourceKind = ClassifyNuGetSource(sourceText);
                var redacted = RedactUrl(sourceText);
                sources.Add(new DependencyPackageSourceInfo(
                    DependencyEcosystem.NuGet,
                    name.Trim(),
                    redacted,
                    relativePath,
                    sourceKind.IsLocal,
                    sourceKind.IsSecureTransport,
                    new Dictionary<string, string> { ["kind"] = sourceKind.Kind }));

                if (!sourceKind.IsSecureTransport)
                {
                    findings.Add(CreateDependencyFinding(
                        "TRUST-DEP013",
                        "NuGet package source uses insecure transport",
                        Severity.High,
                        Confidence.High,
                        $"NuGet package source `{name.Trim()}` uses insecure HTTP transport.",
                        "nuget-source",
                        $"Package source `{name.Trim()}` is `{redacted}`.",
                        relativePath,
                        "Use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport."));
                }

                if (sourceKind.IsLocal)
                {
                    findings.Add(CreateDependencyFinding(
                        "TRUST-DEP014",
                        "NuGet package source uses a local path",
                        Severity.Low,
                        Confidence.Medium,
                        $"NuGet package source `{name.Trim()}` points to a local path.",
                        "nuget-source",
                        $"Package source `{name.Trim()}` is local.",
                        relativePath,
                        "Review local package sources because they can change package origin assumptions and may hide dependency confusion risk."));
                }
            }
        }
    }

    private static bool TryLoadXml(string filePath, List<string> warnings, string relativePath, out XDocument document)
    {
        document = default!;
        if (!RepositoryFileSystem.CanReadAsText(filePath))
        {
            warnings.Add($"Skipped XML file '{relativePath}' because it is too large or not readable as text.");
            return false;
        }

        try
        {
            using var stream = File.OpenRead(filePath);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            });
            document = XDocument.Load(reader, LoadOptions.None);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not parse XML file '{relativePath}': {ex.Message}");
            return false;
        }
    }

    private static bool TryReadText(string filePath, out string content, List<string> warnings, string relativePath)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(filePath))
        {
            warnings.Add($"Skipped dependency manifest '{relativePath}' because it is too large or not readable as text.");
            return false;
        }

        try
        {
            content = File.ReadAllText(filePath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not read dependency manifest '{relativePath}': {ex.Message}");
            return false;
        }
    }

    private static IEnumerable<DependencyPackageInfo> ParseRequirements(string content, string manifestPath)
    {
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal) || line.StartsWith("-"))
            {
                continue;
            }

            var match = PythonRequirementPattern().Match(line.Split('#')[0].Trim());
            if (!match.Success)
            {
                continue;
            }

            var name = match.Groups["name"].Value;
            var version = match.Groups["version"].Success ? match.Groups["version"].Value : null;
            var op = match.Groups["op"].Success ? match.Groups["op"].Value : null;
            yield return new DependencyPackageInfo(
                DependencyEcosystem.Python,
                name,
                NormalizeVersion(version),
                DependencyScope.Production,
                manifestPath,
                null,
                true,
                string.Equals(op, "==", StringComparison.Ordinal),
                IsPrereleaseVersion(version),
                op is null ? null : new Dictionary<string, string> { ["operator"] = op });
        }
    }

    private static IEnumerable<DependencyPackageInfo> ParsePyproject(string content, string manifestPath)
    {
        var inProjectDependencies = false;
        var inPoetryDependencies = false;
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                inProjectDependencies = line.Equals("[project]", StringComparison.OrdinalIgnoreCase);
                inPoetryDependencies = line.Equals("[tool.poetry.dependencies]", StringComparison.OrdinalIgnoreCase) ||
                                       line.Equals("[tool.poetry.group.dev.dependencies]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (inProjectDependencies && line.StartsWith("\"", StringComparison.Ordinal))
            {
                var value = line.Trim().Trim(',').Trim('"');
                foreach (var package in ParseRequirements(value, manifestPath))
                {
                    yield return package;
                }
            }
            else if (inPoetryDependencies && line.Contains('='))
            {
                var parts = line.Split('=', 2);
                var name = parts[0].Trim().Trim('"');
                if (name.Equals("python", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var version = parts[1].Trim().Trim('"', '\'');
                yield return new DependencyPackageInfo(
                    DependencyEcosystem.Python,
                    name,
                    NormalizeVersion(version),
                    line.Contains("group.dev", StringComparison.OrdinalIgnoreCase) ? DependencyScope.Development : DependencyScope.Production,
                    manifestPath,
                    null,
                    true,
                    IsPinnedPythonVersion(version),
                    IsPrereleaseVersion(version));
            }
        }
    }

    private static IEnumerable<DependencyPackageInfo> ParsePipfile(string content, string manifestPath)
    {
        var scope = DependencyScope.Unknown;
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Equals("[packages]", StringComparison.OrdinalIgnoreCase))
            {
                scope = DependencyScope.Production;
                continue;
            }

            if (line.Equals("[dev-packages]", StringComparison.OrdinalIgnoreCase))
            {
                scope = DependencyScope.Development;
                continue;
            }

            if (scope == DependencyScope.Unknown || string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal) || !line.Contains('='))
            {
                continue;
            }

            var parts = line.Split('=', 2);
            var name = parts[0].Trim().Trim('"');
            var version = parts[1].Trim().Trim('"', '\'');
            yield return new DependencyPackageInfo(
                DependencyEcosystem.Python,
                name,
                NormalizeVersion(version),
                scope,
                manifestPath,
                null,
                true,
                IsPinnedPythonVersion(version),
                IsPrereleaseVersion(version));
        }
    }

    private static void AddPythonVersionFindings(DependencyPackageInfo package, List<Finding> findings)
    {
        if (!package.IsVersionPinned)
        {
            findings.Add(CreateDependencyFinding(
                "TRUST-DEP009",
                "Python requirement is unpinned",
                Severity.Medium,
                Confidence.High,
                $"Python dependency `{package.Name}` is not pinned to an exact version.",
                "python-package",
                $"Package `{package.Name}` version is `{DisplayVersion(package.Version)}`.",
                package.ManifestPath,
                "Pin Python requirements or use a lockfile-based package manager."));
        }

        if (package.IsPrerelease)
        {
            findings.Add(CreateDependencyFinding(
                "TRUST-DEP010",
                "Python dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"Python dependency `{package.Name}` uses prerelease version `{package.Version}`.",
                "python-package",
                $"Package `{package.Name}` version is `{package.Version}`.",
                package.ManifestPath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private static Finding CreateDependencyFinding(
        string ruleId,
        string title,
        Severity severity,
        Confidence confidence,
        string message,
        string evidenceKind,
        string evidence,
        string filePath,
        string recommendation) =>
        new(
            ruleId,
            title,
            AnalysisCategory.Dependencies,
            severity,
            confidence,
            message,
            [new Evidence(evidenceKind, evidence, filePath)],
            new Recommendation(recommendation));

    private static IReadOnlyDictionary<string, string> BuildMetrics(
        IReadOnlyList<DependencyManifestInfo> manifests,
        IReadOnlyList<DependencyLockfileInfo> lockfiles,
        IReadOnlyList<DependencyPackageInfo> packages,
        IReadOnlyList<DependencyPackageSourceInfo> sources)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.manifest.count"] = manifests.Count.ToString(),
            ["dependency.lockfile.count"] = lockfiles.Count.ToString(),
            ["dependency.package.count"] = packages.Count.ToString(),
            ["dependency.package.direct.count"] = packages.Count(package => package.IsDirect).ToString(),
            ["dependency.package.unpinned.count"] = packages.Count(package => !package.IsVersionPinned).ToString(),
            ["dependency.package.prerelease.count"] = packages.Count(package => package.IsPrerelease).ToString(),
            ["dependency.source.count"] = sources.Count.ToString(),
            ["dependency.source.insecure.count"] = sources.Count(source => !source.IsSecureTransport).ToString(),
            ["dependency.source.local.count"] = sources.Count(source => source.IsLocal).ToString(),
            ["dependency.package.npm.remote-source.count"] = packages.Count(package =>
                package.Ecosystem == DependencyEcosystem.Npm &&
                package.Metadata?.TryGetValue("sourceKind", out var kind) == true &&
                kind.Equals("remote", StringComparison.OrdinalIgnoreCase)).ToString(),
            ["dependency.package.npm.local-source.count"] = packages.Count(package =>
                package.Ecosystem == DependencyEcosystem.Npm &&
                package.Metadata?.TryGetValue("sourceKind", out var kind) == true &&
                kind.Equals("local", StringComparison.OrdinalIgnoreCase)).ToString()
        };

        foreach (var group in packages.GroupBy(package => package.Ecosystem))
        {
            metrics[$"dependency.package.{group.Key.ToString().ToLowerInvariant()}.count"] = group.Count().ToString();
        }

        foreach (var group in manifests.GroupBy(manifest => manifest.Ecosystem))
        {
            metrics[$"dependency.manifest.{group.Key.ToString().ToLowerInvariant()}.count"] = group.Count().ToString();
        }

        return metrics;
    }

    private static string? ReadXmlAttribute(XElement element, string name) =>
        element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == name)?.Value;

    private static string Relative(AnalysisContext context, string filePath) =>
        Path.GetRelativePath(context.RepositoryPath, filePath).Replace('\\', '/');

    private static string NormalizePackageName(string name) => name.Trim();

    private static string? NormalizeVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        return version.Trim();
    }

    private static bool IsPinnedNuGetVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        !version.Contains('*', StringComparison.Ordinal) &&
        !version.Contains('[', StringComparison.Ordinal) &&
        !version.Contains(']', StringComparison.Ordinal) &&
        !version.Contains('(', StringComparison.Ordinal) &&
        !version.Contains(')', StringComparison.Ordinal);

    private static bool IsPinnedNpmVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        ExactSemVerPattern().IsMatch(version);

    private static bool IsPinnedPythonVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        ExactSemVerPattern().IsMatch(version);

    private static bool IsPrereleaseVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        Regex.IsMatch(version, @"\d+\.\d+(\.\d+)?[-][0-9A-Za-z]", RegexOptions.CultureInvariant);

    private static string DisplayVersion(string? version) => string.IsNullOrWhiteSpace(version) ? "missing" : version;

    private static NpmSourceKind ClassifyNpmVersionSpec(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return new NpmSourceKind("registry", false, false);
        }

        var value = version.Trim();
        if (value.StartsWith("git+", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("git://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("github:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            value.Contains(".git#", StringComparison.OrdinalIgnoreCase))
        {
            return new NpmSourceKind("remote", true, false);
        }

        if (value.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("link:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("workspace:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("portal:", StringComparison.OrdinalIgnoreCase))
        {
            return new NpmSourceKind("local", false, true);
        }

        return new NpmSourceKind("registry", false, false);
    }

    private static NuGetSourceKind ClassifyNuGetSource(string source)
    {
        if (Uri.TryCreate(source, UriKind.Absolute, out var uri))
        {
            if (uri.IsFile)
            {
                return new NuGetSourceKind("local", true, true);
            }

            return new NuGetSourceKind(uri.Scheme, false, uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
        }

        return new NuGetSourceKind("local", true, true);
    }

    private static string RedactUrl(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.UserInfo))
        {
            var builder = new UriBuilder(uri) { UserName = "***", Password = "***" };
            return builder.Uri.ToString();
        }

        return value;
    }

    [GeneratedRegex(@"^(?<name>[A-Za-z0-9_.-]+)\s*(?<op>===|==|~=|!=|<=|>=|<|>)?\s*(?<version>[^\s;]+)?", RegexOptions.CultureInvariant)]
    private static partial Regex PythonRequirementPattern();

    [GeneratedRegex(@"^\d+\.\d+(\.\d+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactSemVerPattern();

    private sealed record NpmSourceKind(string Kind, bool IsRemote, bool IsLocal);

    private sealed record NuGetSourceKind(string Kind, bool IsLocal, bool IsSecureTransport);
}

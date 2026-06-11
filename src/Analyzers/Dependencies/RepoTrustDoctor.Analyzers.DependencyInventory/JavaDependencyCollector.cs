using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class JavaDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["gradle.lockfile", "dependencies.lock", "maven-dependency-lock.json"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Maven,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        var pomFiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pom.xml").ToArray();
        var gradleFiles = RepositoryFileSystem
            .EnumerateFiles(context.RepositoryPath, "build.gradle")
            .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "build.gradle.kts"))
            .ToArray();
        var catalogFiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "libs.versions.toml").ToArray();

        AddMissingLockfileFinding(context, pomFiles, gradleFiles, state);

        foreach (var pom in pomFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeMavenPom(context, pom, state);
        }

        foreach (var gradle in gradleFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeGradleBuild(context, gradle, state);
        }

        foreach (var catalog in catalogFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeGradleVersionCatalog(context, catalog, state);
        }

        AddGradleWrapperFinding(context, gradleFiles, state);
        AnalyzeSpringConfigurations(context, state, cancellationToken);
    }

    private static void AddMissingLockfileFinding(
        AnalysisContext context,
        IReadOnlyCollection<string> pomFiles,
        IReadOnlyCollection<string> gradleFiles,
        DependencyInventoryState state)
    {
        if ((pomFiles.Count == 0 && gradleFiles.Count == 0) ||
            state.Lockfiles.Any(lockfile => lockfile.Ecosystem == DependencyEcosystem.Maven))
        {
            return;
        }

        var firstManifest = pomFiles.FirstOrDefault() ?? gradleFiles.First();
        state.Findings.Add(new Finding(
            "TRUST-DEP017",
            "Java dependency manifest does not have a recognized lockfile",
            AnalysisCategory.Dependencies,
            Severity.Low,
            Confidence.Medium,
            "Java dependency manifest does not have a recognized lockfile",
            [new Evidence("package-manifest", "A Maven or Gradle manifest exists but no recognized dependency lockfile was found.", DependencyInventorySupport.Relative(context, firstManifest))],
            new Recommendation("Commit Gradle dependency locking output or equivalent dependency lock evidence for repeatable Java builds.")));
    }

    private static void AnalyzeMavenPom(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Maven, relativePath, "pom.xml"));

        if (!DependencyInventorySupport.TryLoadXml(filePath, state.Warnings, relativePath, out var document))
        {
            return;
        }

        var properties = ReadMavenProperties(document.Root);
        foreach (var dependency in document.Descendants().Where(IsMavenDependencyElement))
        {
            var groupId = dependency.Elements().FirstOrDefault(element => element.Name.LocalName == "groupId")?.Value.Trim();
            var artifactId = dependency.Elements().FirstOrDefault(element => element.Name.LocalName == "artifactId")?.Value.Trim();
            if (string.IsNullOrWhiteSpace(groupId) || string.IsNullOrWhiteSpace(artifactId))
            {
                continue;
            }

            var declaredVersion = dependency.Elements().FirstOrDefault(element => element.Name.LocalName == "version")?.Value.Trim();
            var resolvedVersion = ResolveMavenVersion(declaredVersion, properties, out var versionSource);
            var scopeText = dependency.Elements().FirstOrDefault(element => element.Name.LocalName == "scope")?.Value.Trim();
            var metadata = BuildMavenMetadata(declaredVersion, versionSource);

            AddJavaPackage(
                relativePath,
                $"{groupId}:{artifactId}",
                resolvedVersion,
                MapMavenScope(scopeText),
                metadata,
                state);
        }
    }

    private static void AnalyzeGradleBuild(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Maven, relativePath, Path.GetFileName(filePath)));

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        foreach (Match match in GradleDependencyPattern().Matches(content))
        {
            var coordinates = match.Groups["coordinates"].Value.Split(':', StringSplitOptions.TrimEntries);
            if (coordinates.Length < 2)
            {
                continue;
            }

            AddJavaPackage(
                relativePath,
                $"{coordinates[0]}:{coordinates[1]}",
                coordinates.Length > 2 ? coordinates[2] : null,
                MapGradleScope(match.Groups["configuration"].Value),
                new Dictionary<string, string> { ["configuration"] = match.Groups["configuration"].Value },
                state);
        }
    }

    private static void AnalyzeGradleVersionCatalog(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Maven, relativePath, "libs.versions.toml"));

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        string? currentSection = null;
        var lines = content.Split('\n');

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                continue;

            // Track section headers
            if (line is "[versions]" or "[libraries]" or "[plugins]")
            {
                currentSection = line.Trim('[', ']');
                continue;
            }
            if (line.StartsWith('['))
            {
                currentSection = null;
                continue;
            }

            if (currentSection is null)
                continue;

            // Extract version from "name = "value"" or "name = { ..., version = "value" }"
            var version = ExtractTomlVersion(line);
            if (version is null)
                continue;

            if (IsDynamicVersion(version))
            {
                var ruleId = currentSection == "plugins" ? "TRUST-DEP051" : "TRUST-DEP050";
                var finding = new Finding(
                    ruleId,
                    "Gradle version catalog uses dynamic version",
                    AnalysisCategory.Dependencies,
                    Severity.Medium,
                    Confidence.High,
                    $"Version catalog declares dynamic version '{version}'.",
                    [new Evidence("version-catalog", $"Dynamic version '{version}' in {currentSection} section.", relativePath)],
                    new Recommendation("Pin dependency versions to specific releases for reproducible builds."));

                if (!state.Findings.Any(f => f.RuleId == ruleId && f.Evidence.Any(e => e.FilePath == relativePath)))
                {
                    state.Findings.Add(finding);
                }
            }
        }
    }

    private static string? ExtractTomlVersion(string line)
    {
        // Simple "name = "version"" form in [versions]
        var simpleMatch = TomlSimpleVersionPattern().Match(line);
        if (simpleMatch.Success)
            return simpleMatch.Groups["version"].Value;

        // Inline table form: "name = { ..., version = "version", ... }" in [libraries] or [plugins]
        var inlineMatch = TomlInlineVersionPattern().Match(line);
        if (inlineMatch.Success)
            return inlineMatch.Groups["version"].Value;

        return null;
    }

    private static bool IsDynamicVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return false;

        return version.Contains('+') ||
               version.Contains("latest.release", StringComparison.OrdinalIgnoreCase) ||
               version.Contains("latest.integration", StringComparison.OrdinalIgnoreCase) ||
               version.Contains('[') || version.Contains('(');
    }

    private static void AddJavaPackage(
        string relativePath,
        string name,
        string? version,
        DependencyScope scope,
        IReadOnlyDictionary<string, string>? metadata,
        DependencyInventoryState state)
    {
        var normalizedVersion = DependencyInventorySupport.NormalizeVersion(version);
        var pinned = IsPinnedVersion(normalizedVersion);
        var prerelease = IsJavaPrerelease(normalizedVersion);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Maven,
            name,
            normalizedVersion,
            scope,
            relativePath,
            null,
            true,
            pinned,
            prerelease,
            metadata));

        AddVersionFindings(relativePath, name, normalizedVersion, pinned, prerelease, state);
    }

    private static void AddVersionFindings(
        string relativePath,
        string name,
        string? version,
        bool pinned,
        bool prerelease,
        DependencyInventoryState state)
    {
        if (!pinned)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP018",
                "Java dependency uses a dynamic or unpinned version",
                Severity.Medium,
                Confidence.High,
                $"Java dependency `{name}` uses a dynamic or unpinned version.",
                "java-package",
                $"Package `{name}` version is `{DependencyInventorySupport.DisplayVersion(version)}`.",
                relativePath,
                "Pin Java dependency versions or resolve them through a reviewed platform/BOM."));
        }

        if (prerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP019",
                "Java dependency uses a snapshot or prerelease version",
                Severity.Low,
                Confidence.High,
                $"Java dependency `{name}` uses snapshot or prerelease version `{version}`.",
                "java-package",
                $"Package `{name}` version is `{version}`.",
                relativePath,
                "Review whether the Java prerelease dependency is intentional before production use."));
        }
    }

    private static void AddGradleWrapperFinding(AnalysisContext context, IReadOnlyCollection<string> gradleFiles, DependencyInventoryState state)
    {
        if (gradleFiles.Count == 0)
        {
            return;
        }

        var hasWrapper = File.Exists(Path.Combine(context.RepositoryPath, "gradlew")) &&
                         File.Exists(Path.Combine(context.RepositoryPath, "gradle", "wrapper", "gradle-wrapper.properties"));
        if (hasWrapper)
        {
            return;
        }

        state.Findings.Add(new Finding(
            "TRUST-DEP020",
            "Gradle project does not include wrapper scripts",
            AnalysisCategory.Dependencies,
            Severity.Low,
            Confidence.Medium,
            "Gradle project does not include wrapper scripts.",
            [new Evidence("package-manifest", "A Gradle build exists but gradlew and gradle-wrapper.properties were not found.", DependencyInventorySupport.Relative(context, gradleFiles.First()))],
            new Recommendation("Commit gradlew, gradlew.bat, and the wrapper properties file so reviewers can see the expected Gradle distribution.")));
    }

    private static void AnalyzeSpringConfigurations(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        var files = RepositoryFileSystem
            .EnumerateFiles(context.RepositoryPath, "application.properties")
            .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "application.yml"))
            .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "application.yaml"));

        foreach (var filePath in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = DependencyInventorySupport.Relative(context, filePath);
            if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath) ||
                !SpringActuatorExposurePattern().IsMatch(content))
            {
                continue;
            }

            state.Findings.Add(new Finding(
                "TRUST-DEP021",
                "Spring Boot Actuator exposes broad endpoint access",
                AnalysisCategory.Dependencies,
                Severity.High,
                Confidence.Medium,
                "Spring Boot Actuator appears configured to expose all web endpoints.",
                [new Evidence("spring-config", "management.endpoints.web.exposure.include appears to expose all endpoints.", relativePath)],
                new Recommendation("Restrict management.endpoints.web.exposure.include to the minimum required endpoints and protect management interfaces.")));
        }
    }

    private static Dictionary<string, string> ReadMavenProperties(System.Xml.Linq.XElement? root)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var propertiesElement = root?.Elements().FirstOrDefault(element => element.Name.LocalName == "properties");
        if (propertiesElement is null)
        {
            return properties;
        }

        foreach (var element in propertiesElement.Elements())
        {
            properties[element.Name.LocalName] = element.Value.Trim();
        }

        return properties;
    }

    private static bool IsMavenDependencyElement(System.Xml.Linq.XElement element) =>
        element.Name.LocalName == "dependency" &&
        !element.Ancestors().Any(ancestor => ancestor.Name.LocalName == "dependencyManagement");

    private static string? ResolveMavenVersion(string? version, IReadOnlyDictionary<string, string> properties, out string? versionSource)
    {
        versionSource = null;
        if (string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var match = MavenPropertyPattern().Match(version);
        if (match.Success && properties.TryGetValue(match.Groups["name"].Value, out var resolved))
        {
            versionSource = "property";
            return resolved;
        }

        return version;
    }

    private static IReadOnlyDictionary<string, string>? BuildMavenMetadata(string? declaredVersion, string? versionSource)
    {
        if (versionSource is null || string.IsNullOrWhiteSpace(declaredVersion))
        {
            return null;
        }

        return new Dictionary<string, string>
        {
            ["versionSource"] = versionSource,
            ["declaredVersion"] = declaredVersion
        };
    }

    private static DependencyScope MapMavenScope(string? scope) =>
        scope?.ToLowerInvariant() switch
        {
            "test" or "provided" => DependencyScope.Development,
            "runtime" or "compile" or null or "" => DependencyScope.Production,
            _ => DependencyScope.Unknown
        };

    private static DependencyScope MapGradleScope(string configuration) =>
        configuration.ToLowerInvariant() switch
        {
            "testimplementation" or "testcompileonly" or "testcompile" or "testapi" => DependencyScope.Development,
            "compileonly" or "annotationprocessor" => DependencyScope.Development,
            "runtimeonly" or "implementation" or "api" or "compile" => DependencyScope.Production,
            _ => DependencyScope.Unknown
        };

    private static bool IsPinnedVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        !version.Contains("${", StringComparison.Ordinal) &&
        !version.Contains('+', StringComparison.Ordinal) &&
        !version.Contains('[', StringComparison.Ordinal) &&
        !version.Contains(']', StringComparison.Ordinal) &&
        !version.Contains('(', StringComparison.Ordinal) &&
        !version.Contains(')', StringComparison.Ordinal) &&
        !version.Equals("LATEST", StringComparison.OrdinalIgnoreCase) &&
        !version.Equals("RELEASE", StringComparison.OrdinalIgnoreCase);

    private static bool IsJavaPrerelease(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        (version.Contains("SNAPSHOT", StringComparison.OrdinalIgnoreCase) ||
         JavaPrereleasePattern().IsMatch(version));

    [GeneratedRegex(@"^\$\{(?<name>[^}]+)\}$", RegexOptions.CultureInvariant)]
    private static partial Regex MavenPropertyPattern();

    [GeneratedRegex(@"(?m)^\s*(?<configuration>implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|annotationProcessor|compile|testCompile)\s*(?:\(|\s+)[""'](?<coordinates>[^""']+)[""']", RegexOptions.CultureInvariant)]
    private static partial Regex GradleDependencyPattern();

    [GeneratedRegex(@"\d+\.\d+(\.\d+)?[-.](alpha|beta|milestone|m|rc|cr|preview)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JavaPrereleasePattern();

    [GeneratedRegex(@"(?mi)^\s*management\.endpoints\.web\.exposure\.include\s*[:=]\s*(?:['""]?\*['""]?|.*\*)\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex SpringActuatorExposurePattern();

    [GeneratedRegex(@"^\s*(?:\w[\w.-]*)\s*=\s*""(?<version>[^""]+)""\s*$")]
    private static partial Regex TomlSimpleVersionPattern();

    [GeneratedRegex(@"version\s*=\s*""(?<version>[^""]+)""")]
    private static partial Regex TomlInlineVersionPattern();
}

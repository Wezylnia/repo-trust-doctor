using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class NuGetDependencyCollector : IDependencyInventoryCollector
{
    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        var projects = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.csproj").ToArray();
        var centralVersions = ReadCentralPackageVersions(context, state.Warnings);

        foreach (var lockfile in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "packages.lock.json"))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.NuGet,
                DependencyInventorySupport.Relative(context, lockfile),
                "packages.lock.json"));
        }

        foreach (var config in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "NuGet.config"))
        {
            ReadNuGetSources(context, config, state);
        }

        AddMissingLockfileFinding(context, projects, state);
        foreach (var project in projects)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeProject(context, project, centralVersions, state);
        }

        if (centralVersions.Count > 0)
        {
            state.Manifests.AddRange(RepositoryFileSystem
                .EnumerateFiles(context.RepositoryPath, "Directory.Packages.props")
                .Select(path => new DependencyManifestInfo(
                    DependencyEcosystem.NuGet,
                    DependencyInventorySupport.Relative(context, path),
                    "Directory.Packages.props")));
        }
    }

    private static void AddMissingLockfileFinding(AnalysisContext context, string[] projects, DependencyInventoryState state)
    {
        if (projects.Length == 0 || state.Lockfiles.Any(lockfile => lockfile.Ecosystem == DependencyEcosystem.NuGet))
        {
            return;
        }

        var relativePath = DependencyInventorySupport.Relative(context, projects[0]);
        state.Findings.Add(new Finding(
            "TRUST-DEP002",
            "NuGet project does not use lockfile",
            AnalysisCategory.Dependencies,
            Severity.Low,
            Confidence.Medium,
            "NuGet project does not use lockfile",
            [new Evidence("package-manifest", "A NuGet project exists but no packages.lock.json was found.", relativePath)],
            new Recommendation("Enable NuGet lock files and restore locked mode, then commit packages.lock.json to the repository.")));
    }

    private static void AnalyzeProject(
        AnalysisContext context,
        string project,
        IReadOnlyDictionary<string, string> centralVersions,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, project);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.NuGet, relativePath, ".csproj"));

        if (!DependencyInventorySupport.TryLoadXml(project, state.Warnings, relativePath, out var document))
        {
            return;
        }

        var projectScope = InferProjectScope(relativePath, document);
        foreach (var reference in document.Descendants().Where(element => element.Name.LocalName == "PackageReference"))
        {
            var name = DependencyInventorySupport.ReadXmlAttribute(reference, "Include") ??
                       DependencyInventorySupport.ReadXmlAttribute(reference, "Update");
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var version = DependencyInventorySupport.ReadXmlAttribute(reference, "Version") ??
                          reference.Elements().FirstOrDefault(element => element.Name.LocalName == "Version")?.Value;

            if (string.IsNullOrWhiteSpace(version) && centralVersions.TryGetValue(name.Trim(), out var centralVersion))
            {
                version = centralVersion;
            }

            AddPackage(relativePath, name.Trim(), version, projectScope, state);
        }
    }

    private static void AddPackage(string relativePath, string name, string? version, DependencyScope scope, DependencyInventoryState state)
    {
        var normalizedVersion = DependencyInventorySupport.NormalizeVersion(version);
        var pinned = IsPinnedVersion(normalizedVersion);
        var prerelease = DependencyInventorySupport.IsPrereleaseVersion(normalizedVersion);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.NuGet,
            name,
            normalizedVersion,
            scope,
            relativePath,
            null,
            true,
            pinned,
            prerelease));

        if (!pinned)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP004",
                "NuGet dependency uses a floating or unpinned version",
                Severity.Medium,
                Confidence.High,
                $"NuGet dependency `{name}` is missing an exact pinned version.",
                "nuget-package",
                $"Package `{name}` version is `{DependencyInventorySupport.DisplayVersion(normalizedVersion)}`.",
                relativePath,
                "Pin direct NuGet dependency versions or resolve them through Central Package Management."));
        }

        if (prerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP005",
                "NuGet dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"NuGet dependency `{name}` uses prerelease version `{normalizedVersion}`.",
                "nuget-package",
                $"Package `{name}` version is `{normalizedVersion}`.",
                relativePath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private static DependencyScope InferProjectScope(string relativePath, XDocument document)
    {
        if (IsTestPath(relativePath) ||
            HasPropertyValue(document, "IsTestProject", "true") ||
            document.Descendants().Any(IsKnownTestPackageReference))
        {
            return DependencyScope.Development;
        }

        return DependencyScope.Production;
    }

    private static bool IsTestPath(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');
        var fileName = Path.GetFileNameWithoutExtension(normalized);
        return normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".Tests", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".Test", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasPropertyValue(XDocument document, string propertyName, string expectedValue) =>
        document.Descendants().Any(element =>
            element.Name.LocalName == propertyName &&
            string.Equals(element.Value.Trim(), expectedValue, StringComparison.OrdinalIgnoreCase));

    private static bool IsKnownTestPackageReference(XElement element)
    {
        if (element.Name.LocalName != "PackageReference")
        {
            return false;
        }

        var name = DependencyInventorySupport.ReadXmlAttribute(element, "Include") ??
                   DependencyInventorySupport.ReadXmlAttribute(element, "Update");
        return name is not null && (
            name.Equals("Microsoft.NET.Test.Sdk", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("xunit", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("NUnit", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("MSTest.", StringComparison.OrdinalIgnoreCase));
    }

    private static Dictionary<string, string> ReadCentralPackageVersions(AnalysisContext context, List<string> warnings)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var props in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Directory.Packages.props"))
        {
            var relativePath = DependencyInventorySupport.Relative(context, props);
            if (!DependencyInventorySupport.TryLoadXml(props, warnings, relativePath, out var document))
            {
                continue;
            }

            foreach (var packageVersion in document.Descendants().Where(element => element.Name.LocalName == "PackageVersion"))
            {
                var name = DependencyInventorySupport.ReadXmlAttribute(packageVersion, "Include") ??
                           DependencyInventorySupport.ReadXmlAttribute(packageVersion, "Update");
                var version = DependencyInventorySupport.ReadXmlAttribute(packageVersion, "Version");
                if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(version))
                {
                    versions[name.Trim()] = version.Trim();
                }
            }
        }

        return versions;
    }

    private static void ReadNuGetSources(AnalysisContext context, string configPath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, configPath);
        if (!DependencyInventorySupport.TryLoadXml(configPath, state.Warnings, relativePath, out var document))
        {
            return;
        }

        foreach (var source in document.Descendants().Where(IsPackageSourceAddElement))
        {
            var name = DependencyInventorySupport.ReadXmlAttribute(source, "key");
            var value = DependencyInventorySupport.ReadXmlAttribute(source, "value");
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            AddSource(relativePath, name.Trim(), value.Trim(), state);
        }
    }

    private static void AddSource(string relativePath, string name, string sourceText, DependencyInventoryState state)
    {
        var sourceKind = ClassifySource(sourceText);
        var redacted = RedactUrl(sourceText);
        state.PackageSources.Add(new DependencyPackageSourceInfo(
            DependencyEcosystem.NuGet,
            name,
            redacted,
            relativePath,
            sourceKind.IsLocal,
            sourceKind.IsSecureTransport,
            new Dictionary<string, string> { ["kind"] = sourceKind.Kind }));

        if (!sourceKind.IsSecureTransport)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP013",
                "NuGet package source uses insecure transport",
                Severity.High,
                Confidence.High,
                $"NuGet package source `{name}` uses insecure HTTP transport.",
                "nuget-source",
                $"Package source `{name}` is `{redacted}`.",
                relativePath,
                "Use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport."));
        }

        if (sourceKind.IsLocal)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP014",
                "NuGet package source uses a local path",
                Severity.Low,
                Confidence.Medium,
                $"NuGet package source `{name}` points to a local path.",
                "nuget-source",
                $"Package source `{name}` is local.",
                relativePath,
                "Review local package sources because they can change package origin assumptions and may hide dependency confusion risk."));
        }
    }

    private static bool IsPackageSourceAddElement(XElement element) =>
        element.Name.LocalName == "add" &&
        element.Ancestors().Any(ancestor => ancestor.Name.LocalName == "packageSources");

    private static bool IsPinnedVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        !version.Contains('*', StringComparison.Ordinal) &&
        !version.Contains('[', StringComparison.Ordinal) &&
        !version.Contains(']', StringComparison.Ordinal) &&
        !version.Contains('(', StringComparison.Ordinal) &&
        !version.Contains(')', StringComparison.Ordinal);

    private static NuGetSourceKind ClassifySource(string source)
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

    private sealed record NuGetSourceKind(string Kind, bool IsLocal, bool IsSecureTransport);
}

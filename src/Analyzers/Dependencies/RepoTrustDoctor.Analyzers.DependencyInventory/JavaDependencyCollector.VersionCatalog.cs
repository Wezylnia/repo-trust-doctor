using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class JavaDependencyCollector
{
    private static void AnalyzeGradleVersionCatalog(
        AnalysisContext context,
        string filePath,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(
            DependencyEcosystem.Maven,
            relativePath,
            "libs.versions.toml"));

        if (!DependencyInventorySupport.TryReadText(
                filePath,
                out var content,
                state.Warnings,
                relativePath))
        {
            return;
        }

        var catalog = GradleVersionCatalogParser.Parse(content);
        foreach (var version in catalog.Versions.Values)
        {
            if (IsDynamicCatalogVersion(version))
            {
                AddCatalogFinding(
                    "TRUST-DEP050",
                    "Gradle version catalog uses dynamic dependency version",
                    version,
                    "versions",
                    relativePath,
                    state);
            }
        }

        foreach (var library in catalog.Libraries)
        {
            var version = ResolveCatalogVersion(library, catalog.Versions, out var versionSource);
            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["catalogAlias"] = library.Alias
            };
            if (versionSource is not null)
            {
                metadata["versionSource"] = versionSource;
            }
            if (library.VersionReference is not null)
            {
                metadata["versionReference"] = library.VersionReference;
            }

            var suppressUnpinnedFinding =
                DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath) ||
                IsDynamicCatalogVersion(version);
            var confidence = library.VersionReference is not null && version is null
                ? Confidence.Medium
                : Confidence.High;
            AddJavaPackage(
                relativePath,
                library.Module,
                version,
                DependencyScope.Production,
                metadata,
                suppressUnpinnedFinding,
                confidence,
                state);

            if (IsDynamicCatalogVersion(version))
            {
                AddCatalogFinding(
                    "TRUST-DEP050",
                    "Gradle version catalog uses dynamic dependency version",
                    version!,
                    "libraries",
                    relativePath,
                    state);
            }
        }

        foreach (var plugin in catalog.Plugins)
        {
            var version = plugin.Version ??
                          ResolveVersionReference(plugin.VersionReference, catalog.Versions);
            if (IsDynamicCatalogVersion(version))
            {
                AddCatalogFinding(
                    "TRUST-DEP051",
                    "Gradle version catalog uses dynamic plugin version",
                    version!,
                    "plugins",
                    relativePath,
                    state);
            }
        }
    }

    private static string? ResolveCatalogVersion(
        GradleCatalogLibrary library,
        IReadOnlyDictionary<string, string> versions,
        out string? versionSource)
    {
        if (!string.IsNullOrWhiteSpace(library.Version))
        {
            versionSource = "gradle-version-catalog";
            return library.Version;
        }

        if (!string.IsNullOrWhiteSpace(library.VersionReference))
        {
            versionSource = versions.ContainsKey(library.VersionReference)
                ? "gradle-version-catalog-ref"
                : "gradle-version-catalog-ref-unresolved";
            return ResolveVersionReference(library.VersionReference, versions);
        }

        versionSource = "gradle-version-catalog-unversioned";
        return null;
    }

    private static string? ResolveVersionReference(
        string? reference,
        IReadOnlyDictionary<string, string> versions) =>
        !string.IsNullOrWhiteSpace(reference) &&
        versions.TryGetValue(reference, out var version)
            ? version
            : null;

    private static void AddCatalogFinding(
        string ruleId,
        string title,
        string version,
        string section,
        string relativePath,
        DependencyInventoryState state)
    {
        if (state.Findings.Any(finding =>
                finding.RuleId == ruleId &&
                finding.Evidence.Any(evidence => evidence.FilePath == relativePath)))
        {
            return;
        }

        state.Findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.Dependencies,
            Severity.Medium,
            Confidence.High,
            $"Version catalog declares dynamic version '{version}'.",
            [new Evidence(
                "version-catalog",
                $"Dynamic version '{version}' in {section} section.",
                relativePath)],
            new Recommendation("Pin dependency versions to specific releases for reproducible builds.")));
    }

    private static bool IsDynamicCatalogVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        (version.Contains('+') ||
         version.Contains("latest.release", StringComparison.OrdinalIgnoreCase) ||
         version.Contains("latest.integration", StringComparison.OrdinalIgnoreCase) ||
         version.Contains('[') ||
         version.Contains('('));
}

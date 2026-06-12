using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class JavaDependencyCollector
{
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

    [GeneratedRegex(@"^\s*(?:\w[\w.-]*)\s*=\s*""(?<version>[^""]+)""\s*$")]
    private static partial Regex TomlSimpleVersionPattern();

    [GeneratedRegex(@"version\s*=\s*""(?<version>[^""]+)""")]
    private static partial Regex TomlInlineVersionPattern();
}


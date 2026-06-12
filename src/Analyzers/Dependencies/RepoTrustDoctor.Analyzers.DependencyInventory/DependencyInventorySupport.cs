using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal interface IDependencyInventoryCollector
{
    void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken);
}

internal sealed class DependencyInventoryState
{
    public List<Finding> Findings { get; } = [];

    public List<string> Warnings { get; } = [];

    public List<DependencyManifestInfo> Manifests { get; } = [];

    public List<DependencyLockfileInfo> Lockfiles { get; } = [];

    public List<DependencyPackageInfo> Packages { get; } = [];

    public List<DependencyPackageSourceInfo> PackageSources { get; } = [];
}

internal static partial class DependencyInventorySupport
{
    public static string Relative(AnalysisContext context, string filePath) =>
        Path.GetRelativePath(context.RepositoryPath, filePath).Replace('\\', '/');

    public static bool TryReadText(string filePath, out string content, List<string> warnings, string relativePath)
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

    public static bool TryLoadXml(string filePath, List<string> warnings, string relativePath, out XDocument document)
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

    public static string? ReadXmlAttribute(XElement element, string name) =>
        element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == name)?.Value;

    public static string? NormalizeVersion(string? version) =>
        string.IsNullOrWhiteSpace(version) ? null : version.Trim();

    public static string DisplayVersion(string? version) =>
        string.IsNullOrWhiteSpace(version) ? "missing" : version;

    public static string[] SplitLines(string content) =>
        content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');

    public static bool IsPrereleaseVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        Regex.IsMatch(version, @"\d+\.\d+(\.\d+)?[-][0-9A-Za-z]", RegexOptions.CultureInvariant);

    public static bool IsLikelyExampleOrTestPath(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');
        return normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("__tests__/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/__tests__/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("fixtures/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("examples/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/examples/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("playground/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/playground/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("testdata/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/testdata/", StringComparison.OrdinalIgnoreCase);
    }

    public static Finding CreateDependencyFinding(
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

    [GeneratedRegex(@"^\d+\.\d+(\.\d+)?$", RegexOptions.CultureInvariant)]
    public static partial Regex ExactSemVerPattern();
}

internal static class DependencyInventoryMetrics
{
    public static IReadOnlyDictionary<string, string> Build(DependencyInventoryState state)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["dependency.manifest.count"] = state.Manifests.Count.ToString(),
            ["dependency.lockfile.count"] = state.Lockfiles.Count.ToString(),
            ["dependency.package.count"] = state.Packages.Count.ToString(),
            ["dependency.package.direct.count"] = state.Packages.Count(package => package.IsDirect).ToString(),
            ["dependency.package.unpinned.count"] = state.Packages.Count(package => !package.IsVersionPinned).ToString(),
            ["dependency.package.prerelease.count"] = state.Packages.Count(package => package.IsPrerelease).ToString(),
            ["dependency.source.count"] = state.PackageSources.Count.ToString(),
            ["dependency.source.insecure.count"] = state.PackageSources.Count(source => !source.IsSecureTransport).ToString(),
            ["dependency.source.local.count"] = state.PackageSources.Count(source => source.IsLocal).ToString(),
            ["dependency.package.npm.remote-source.count"] = state.Packages.Count(package =>
                package.Ecosystem == DependencyEcosystem.Npm &&
                package.Metadata?.TryGetValue("sourceKind", out var kind) == true &&
                kind.Equals("remote", StringComparison.OrdinalIgnoreCase)).ToString(),
            ["dependency.package.npm.local-source.count"] = state.Packages.Count(package =>
                package.Ecosystem == DependencyEcosystem.Npm &&
                package.Metadata?.TryGetValue("sourceKind", out var kind) == true &&
                kind.Equals("local", StringComparison.OrdinalIgnoreCase)).ToString()
        };

        foreach (var group in state.Packages.GroupBy(package => package.Ecosystem))
        {
            metrics[$"dependency.package.{group.Key.ToString().ToLowerInvariant()}.count"] = group.Count().ToString();
        }

        foreach (var group in state.Manifests.GroupBy(manifest => manifest.Ecosystem))
        {
            metrics[$"dependency.manifest.{group.Key.ToString().ToLowerInvariant()}.count"] = group.Count().ToString();
        }

        return metrics;
    }
}

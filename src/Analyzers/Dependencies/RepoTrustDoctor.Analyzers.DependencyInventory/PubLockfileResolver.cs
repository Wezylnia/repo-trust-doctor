using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class PubLockfileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private PubLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static PubLockfileResolver? TryCreate(
        string lockfilePath,
        string relativePath,
        DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(
                lockfilePath,
                out var content,
                state.Warnings,
                relativePath))
        {
            return null;
        }

        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? packageName = null;
        string? source = null;
        string? version = null;
        foreach (var line in DependencyInventorySupport.SplitLines(content))
        {
            var packageMatch = PackagePattern().Match(line);
            if (packageMatch.Success)
            {
                AddHostedPackage(versions, packageName, source, version);
                packageName = packageMatch.Groups["name"].Value;
                source = null;
                version = null;
                continue;
            }

            if (packageName is null)
            {
                continue;
            }

            var propertyMatch = PropertyPattern().Match(line);
            if (!propertyMatch.Success)
            {
                continue;
            }

            var propertyName = propertyMatch.Groups["name"].Value;
            var propertyValue = propertyMatch.Groups["value"].Value.Trim().Trim('"', '\'');
            if (propertyName.Equals("source", StringComparison.OrdinalIgnoreCase))
            {
                source = propertyValue;
            }
            else if (propertyName.Equals("version", StringComparison.OrdinalIgnoreCase))
            {
                version = propertyValue;
            }
        }

        AddHostedPackage(versions, packageName, source, version);
        return new PubLockfileResolver(relativePath, versions);
    }

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(packageName, out version!);

    private static void AddHostedPackage(
        IDictionary<string, string> versions,
        string? packageName,
        string? source,
        string? version)
    {
        if (!string.IsNullOrWhiteSpace(packageName) &&
            source?.Equals("hosted", StringComparison.OrdinalIgnoreCase) == true &&
            !string.IsNullOrWhiteSpace(version))
        {
            versions[packageName] = version;
        }
    }

    [GeneratedRegex(@"^\s{2}(?<name>[^:\s]+):\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex PackagePattern();

    [GeneratedRegex(
        @"^\s{4}(?<name>source|version):\s*(?<value>.+?)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PropertyPattern();
}

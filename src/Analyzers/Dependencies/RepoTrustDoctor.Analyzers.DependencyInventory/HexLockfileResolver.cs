using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class HexLockfileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private HexLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static HexLockfileResolver? TryCreate(
        string lockfilePath,
        string relativePath,
        DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(lockfilePath, out var content, state.Warnings, relativePath))
        {
            return null;
        }

        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in HexPackagePattern().Matches(content))
        {
            var version = match.Groups["version"].Value;
            versions[match.Groups["key"].Value] = version;
            versions[match.Groups["name"].Value] = version;
        }

        return new HexLockfileResolver(relativePath, versions);
    }

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(packageName, out version!);

    [GeneratedRegex(
        @"(?m)^\s*""(?<key>[^""]+)""\s*:\s*\{:hex,\s*:(?<name>[A-Za-z0-9_.@-]+),\s*""(?<version>[^""]+)""",
        RegexOptions.CultureInvariant)]
    private static partial Regex HexPackagePattern();
}

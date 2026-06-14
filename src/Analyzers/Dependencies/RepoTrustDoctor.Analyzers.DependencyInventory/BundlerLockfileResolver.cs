using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class BundlerLockfileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private BundlerLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static BundlerLockfileResolver? TryCreate(
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
        var inGemSection = false;
        var inSpecs = false;
        foreach (var line in DependencyInventorySupport.SplitLines(content))
        {
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                inGemSection = line.Equals("GEM", StringComparison.Ordinal);
                inSpecs = false;
                continue;
            }

            if (!inGemSection)
            {
                continue;
            }

            if (line.Trim().Equals("specs:", StringComparison.Ordinal))
            {
                inSpecs = true;
                continue;
            }

            if (!inSpecs)
            {
                continue;
            }

            var match = LockedGemPattern().Match(line);
            if (match.Success)
            {
                versions[match.Groups["name"].Value] = match.Groups["version"].Value;
            }
        }

        return new BundlerLockfileResolver(relativePath, versions);
    }

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(packageName, out version!);

    [GeneratedRegex(
        @"^\s{4}(?<name>[A-Za-z0-9_.-]+)\s+\((?<version>[^)\s,]+)(?:,[^)]*)?\)\s*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex LockedGemPattern();
}

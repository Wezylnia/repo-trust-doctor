using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class YarnLockfileResolver : INpmLockfileResolver
{
    private const long MaximumLockfileBytes = 64L * 1024 * 1024;
    private readonly IReadOnlyDictionary<string, string> versionsBySelector;

    private YarnLockfileResolver(IReadOnlyDictionary<string, string> versionsBySelector)
    {
        this.versionsBySelector = versionsBySelector;
    }

    public string VersionSource => "yarn-lock";

    public bool TryResolve(
        string manifestDirectory,
        string packageName,
        string? requestedVersion,
        out string version)
    {
        var selector = BuildSelector(packageName, requestedVersion);
        return versionsBySelector.TryGetValue(selector, out version!) &&
               NpmPackageLockResolver.IsExactVersion(version);
    }

    public static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out YarnLockfileResolver? resolver)
    {
        resolver = null;
        if (!RepositoryFileSystem.CanReadAsText(lockfilePath, MaximumLockfileBytes))
        {
            warnings.Add(
                $"Skipped Yarn lockfile '{relativePath}' because it exceeds the {MaximumLockfileBytes / (1024 * 1024)} MiB lockfile safety limit or is not readable as text.");
            return false;
        }

        try
        {
            resolver = new YarnLockfileResolver(ParseSelectors(lockfilePath));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not read Yarn lockfile '{relativePath}'.");
            return false;
        }
    }

    private static IReadOnlyDictionary<string, string> ParseSelectors(string lockfilePath)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<string> currentSelectors = [];

        using var reader = new StreamReader(lockfilePath);
        while (reader.ReadLine() is { } rawLine)
        {
            if (string.IsNullOrWhiteSpace(rawLine) || rawLine.TrimStart().StartsWith('#'))
            {
                continue;
            }

            if (!char.IsWhiteSpace(rawLine[0]) && rawLine.TrimEnd().EndsWith(':'))
            {
                currentSelectors = ParseHeader(rawLine.Trim());
                continue;
            }

            if (currentSelectors.Count == 0 || !TryReadVersion(rawLine.Trim(), out var version))
            {
                continue;
            }

            foreach (var selector in currentSelectors)
            {
                versions[selector] = version;
            }
        }

        return versions;
    }

    private static IReadOnlyList<string> ParseHeader(string header)
    {
        var value = header[..^1].Trim();
        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Unquote)
            .Select(NormalizeSelector)
            .Where(selector => selector.Length > 0)
            .ToArray();
    }

    private static bool TryReadVersion(string line, out string version)
    {
        version = string.Empty;
        if (!line.StartsWith("version", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rawValue = line["version".Length..].TrimStart(':', ' ');
        version = Unquote(rawValue);
        return NpmPackageLockResolver.IsExactVersion(version);
    }

    private static string NormalizeSelector(string selector)
    {
        var separator = FindVersionSeparator(selector);
        if (separator <= 0 || separator == selector.Length - 1)
        {
            return string.Empty;
        }

        var packageName = selector[..separator];
        var requestedVersion = selector[(separator + 1)..];
        if (requestedVersion.StartsWith("npm:", StringComparison.OrdinalIgnoreCase))
        {
            requestedVersion = requestedVersion["npm:".Length..];
        }

        return BuildSelector(packageName, requestedVersion);
    }

    private static int FindVersionSeparator(string selector)
    {
        if (!selector.StartsWith('@'))
        {
            return selector.IndexOf('@');
        }

        var slash = selector.IndexOf('/');
        return slash < 0 ? -1 : selector.IndexOf('@', slash + 1);
    }

    private static string BuildSelector(string packageName, string? requestedVersion) =>
        $"{packageName.Trim()}@{requestedVersion?.Trim()}";

    private static string Unquote(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length >= 2 &&
               ((trimmed[0] == '"' && trimmed[^1] == '"') ||
                (trimmed[0] == '\'' && trimmed[^1] == '\''))
            ? trimmed[1..^1]
            : trimmed;
    }
}

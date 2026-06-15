using System.Text.Json;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

internal sealed record ReleasePackageVersion(
    string FilePath,
    string? PackageName,
    string Version,
    string Ecosystem);

internal sealed record ReleaseNotesEvidence(
    string FilePath,
    string Text,
    string? LatestVersion,
    bool MentionsVersion);

internal sealed class ReleaseNotesResolver
{
    private static readonly string[] ChangelogNames =
        ["CHANGELOG.md", "CHANGELOG", "HISTORY.md", "RELEASES.md"];

    private readonly string repositoryPath;
    private readonly string? rootChangelog;
    private readonly string? rootChangelogText;
    private readonly string? rootChangelogVersion;
    private readonly LernaPackageMatchers fixedLernaPackageMatchers;

    public ReleaseNotesResolver(
        string repositoryPath,
        string? rootChangelog,
        string? rootChangelogText,
        string? rootChangelogVersion)
    {
        this.repositoryPath = repositoryPath;
        this.rootChangelog = rootChangelog;
        this.rootChangelogText = rootChangelogText;
        this.rootChangelogVersion = rootChangelogVersion;
        fixedLernaPackageMatchers = ReadFixedLernaPackageMatchers(repositoryPath);
    }

    public ReleaseNotesEvidence? Resolve(ReleasePackageVersion packageVersion)
    {
        if (IsRootManifest(packageVersion.FilePath))
        {
            return CreateRootReleaseNotes(packageVersion.Version);
        }

        var localReleaseNotes = ResolveLocalReleaseNotes(packageVersion);
        if (localReleaseNotes is not null)
        {
            return localReleaseNotes;
        }

        if (rootChangelog is null || rootChangelogText is null)
        {
            return null;
        }

        var packageMatch = ReleaseEvidenceParsing.MatchPackageChangelog(
            rootChangelogText,
            packageVersion.PackageName,
            packageVersion.FilePath);
        if (packageMatch.ReferencesPackage)
        {
            return new ReleaseNotesEvidence(
                rootChangelog,
                rootChangelogText,
                packageMatch.Versions.FirstOrDefault(),
                packageMatch.Versions.Any(version => VersionsEqual(version, packageVersion.Version)));
        }

        return IsFixedLernaPackage(packageVersion)
            ? CreateRootReleaseNotes(packageVersion.Version)
            : null;
    }

    private ReleaseNotesEvidence? ResolveLocalReleaseNotes(ReleasePackageVersion packageVersion)
    {
        var packagePath = Path.Combine(
            repositoryPath,
            packageVersion.FilePath.Replace('/', Path.DirectorySeparatorChar));
        var packageDirectory = Path.GetDirectoryName(packagePath);
        var localChangelog = FindChangelog(packageDirectory);
        if (localChangelog is null || !TryReadText(localChangelog, out var text))
        {
            return null;
        }

        return new ReleaseNotesEvidence(
            localChangelog,
            text,
            ReleaseEvidenceParsing.ReadLatestChangelogVersion(text),
            text.Contains(packageVersion.Version, StringComparison.OrdinalIgnoreCase));
    }

    private ReleaseNotesEvidence? CreateRootReleaseNotes(string packageVersion) =>
        rootChangelog is not null && rootChangelogText is not null
            ? new ReleaseNotesEvidence(
                rootChangelog,
                rootChangelogText,
                rootChangelogVersion,
                rootChangelogText.Contains(packageVersion, StringComparison.OrdinalIgnoreCase))
            : null;

    private bool IsFixedLernaPackage(ReleasePackageVersion packageVersion)
    {
        if (packageVersion.Ecosystem != "npm" || fixedLernaPackageMatchers.Includes.Count == 0)
        {
            return false;
        }

        var packageDirectory = Path.GetDirectoryName(
            packageVersion.FilePath.Replace('/', Path.DirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(packageDirectory))
        {
            return false;
        }

        var normalizedDirectory = packageDirectory.Replace('\\', '/');
        return fixedLernaPackageMatchers.Includes.Any(matcher => matcher.IsMatch(normalizedDirectory)) &&
               !fixedLernaPackageMatchers.Excludes.Any(matcher => matcher.IsMatch(normalizedDirectory));
    }

    private static LernaPackageMatchers ReadFixedLernaPackageMatchers(string repositoryPath)
    {
        var path = Path.Combine(repositoryPath, "lerna.json");
        if (!TryReadText(path, out var content))
        {
            return LernaPackageMatchers.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(content);
            if (!document.RootElement.TryGetProperty("version", out var version) ||
                version.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(version.GetString()) ||
                version.GetString()!.Equals("independent", StringComparison.OrdinalIgnoreCase))
            {
                return LernaPackageMatchers.Empty;
            }

            var patterns = document.RootElement.TryGetProperty("packages", out var packages) &&
                           packages.ValueKind == JsonValueKind.Array
                ? packages.EnumerateArray()
                    .Where(item => item.ValueKind == JsonValueKind.String)
                    .Select(item => item.GetString())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Select(item => item!)
                    .ToArray()
                : ["packages/*"];
            return new LernaPackageMatchers(
                patterns
                    .Where(pattern => !pattern.TrimStart().StartsWith('!'))
                    .Select(CreateGlobMatcher)
                    .ToArray(),
                patterns
                    .Where(pattern => pattern.TrimStart().StartsWith('!'))
                    .Select(pattern => CreateGlobMatcher(pattern.TrimStart()[1..]))
                    .ToArray());
        }
        catch (JsonException)
        {
            return LernaPackageMatchers.Empty;
        }
    }

    private static Regex CreateGlobMatcher(string pattern)
    {
        var normalized = pattern.Replace('\\', '/').Trim().TrimStart('.').TrimStart('/');
        var expression = "^" + Regex.Escape(normalized)
            .Replace(@"\*\*", ".*", StringComparison.Ordinal)
            .Replace(@"\*", "[^/]*", StringComparison.Ordinal)
            .Replace(@"\?", "[^/]", StringComparison.Ordinal) + "$";
        var options = RegexOptions.CultureInvariant;
        if (OperatingSystem.IsWindows())
        {
            options |= RegexOptions.IgnoreCase;
        }

        return new Regex(expression, options, TimeSpan.FromMilliseconds(100));
    }

    private static string? FindChangelog(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return null;
        }

        foreach (var name in ChangelogNames)
        {
            var path = Path.Combine(directory, name);
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    private static bool TryReadText(string path, out string content)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(path))
        {
            return false;
        }

        try
        {
            content = File.ReadAllText(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool IsRootManifest(string relativePath) =>
        !relativePath.Contains('/', StringComparison.Ordinal);

    private static bool VersionsEqual(string left, string right) =>
        NormalizeVersion(left).Equals(NormalizeVersion(right), StringComparison.OrdinalIgnoreCase);

    private static string NormalizeVersion(string version) => version.Trim().TrimStart('v');

    private sealed record LernaPackageMatchers(
        IReadOnlyList<Regex> Includes,
        IReadOnlyList<Regex> Excludes)
    {
        public static LernaPackageMatchers Empty { get; } = new([], []);
    }
}

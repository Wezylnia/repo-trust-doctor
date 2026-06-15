using System.Text;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

internal static partial class ReleaseEvidenceParsing
{
    public static string? ReadPyprojectVersion(string content)
        => ReadPyprojectPackage(content).Version;

    public static PyprojectPackage ReadPyprojectPackage(string content)
    {
        string? section = null;
        string? projectName = null;
        string? projectVersion = null;
        string? poetryName = null;
        string? poetryVersion = null;

        foreach (var rawLine in SplitLines(content))
        {
            var line = StripTomlComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line.Trim('[', ']').Trim();
                continue;
            }

            if (section is not ("project" or "tool.poetry"))
            {
                continue;
            }

            var match = PyprojectPropertyPattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var key = match.Groups["key"].Value;
            var value = match.Groups["value"].Value;
            if (section == "project")
            {
                projectName = key == "name" ? value : projectName;
                projectVersion = key == "version" ? value : projectVersion;
            }
            else
            {
                poetryName = key == "name" ? value : poetryName;
                poetryVersion = key == "version" ? value : poetryVersion;
            }
        }

        return !string.IsNullOrWhiteSpace(projectVersion)
            ? new PyprojectPackage(projectName, projectVersion)
            : new PyprojectPackage(poetryName, poetryVersion);
    }

    public static string? ReadLatestChangelogVersion(string content)
    {
        foreach (var line in SplitLines(content))
        {
            var match = ChangelogHeadingPattern().Match(line.Trim());
            if (match.Success)
            {
                return match.Groups["version"].Value;
            }
        }

        return null;
    }

    public static PackageChangelogMatch MatchPackageChangelog(
        string content,
        string? packageName,
        string manifestPath)
    {
        var identities = BuildPackageIdentities(packageName, manifestPath);
        if (identities.Count == 0)
        {
            return new PackageChangelogMatch(false, []);
        }

        var versions = new List<string>();
        var headingVersions = new Dictionary<int, string>();
        int? packageSectionLevel = null;
        var referencesPackage = false;

        foreach (var rawLine in SplitLines(content))
        {
            var line = rawLine.Trim();
            var heading = MarkdownHeadingPattern().Match(line);
            if (!heading.Success)
            {
                if (ContainsIdentity(line, identities))
                {
                    var parentVersion = headingVersions
                        .OrderByDescending(item => item.Key)
                        .Select(item => item.Value)
                        .FirstOrDefault();
                    if (parentVersion is not null)
                    {
                        referencesPackage = true;
                        versions.Add(parentVersion);
                    }
                }

                continue;
            }

            var level = heading.Groups["level"].Value.Length;
            var headingText = heading.Groups["text"].Value.Trim();
            var containsIdentity = ContainsIdentity(headingText, identities);
            var headingVersion = FindFirstVersion(headingText);

            foreach (var deeperLevel in headingVersions.Keys.Where(key => key >= level).ToArray())
            {
                headingVersions.Remove(deeperLevel);
            }

            if (packageSectionLevel is not null &&
                level <= packageSectionLevel &&
                !containsIdentity)
            {
                packageSectionLevel = null;
            }

            if (containsIdentity)
            {
                referencesPackage = true;
                if (headingVersion is not null)
                {
                    versions.Add(headingVersion);
                }
                else
                {
                    var parentVersion = headingVersions
                        .Where(item => item.Key < level)
                        .OrderByDescending(item => item.Key)
                        .Select(item => item.Value)
                        .FirstOrDefault();
                    if (parentVersion is not null)
                    {
                        versions.Add(parentVersion);
                    }

                    packageSectionLevel = level;
                }
            }
            else if (packageSectionLevel is not null &&
                     level > packageSectionLevel &&
                     headingVersion is not null)
            {
                versions.Add(headingVersion);
            }

            if (headingVersion is not null)
            {
                headingVersions[level] = headingVersion;
            }
        }

        return new PackageChangelogMatch(
            referencesPackage,
            versions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public static string RemoveYamlComments(string content)
    {
        var builder = new StringBuilder(content.Length);
        foreach (var line in SplitLines(content))
        {
            builder.AppendLine(StripComment(line));
        }

        return builder.ToString();
    }

    private static string StripComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (quote == '\0' && character is '"' or '\'')
            {
                quote = character;
                continue;
            }

            if (character == quote && (index == 0 || line[index - 1] != '\\'))
            {
                quote = '\0';
                continue;
            }

            if (quote == '\0' &&
                character == '#' &&
                (index == 0 || char.IsWhiteSpace(line[index - 1])))
            {
                return line[..index];
            }
        }

        return line;
    }

    private static string StripTomlComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (quote == '\0' && character is '"' or '\'')
            {
                quote = character;
            }
            else if (character == quote && (index == 0 || line[index - 1] != '\\'))
            {
                quote = '\0';
            }
            else if (quote == '\0' && character == '#')
            {
                return line[..index];
            }
        }

        return line;
    }

    private static IEnumerable<string> SplitLines(string content) =>
        content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');

    private static IReadOnlyList<string> BuildPackageIdentities(
        string? packageName,
        string manifestPath)
    {
        var identities = new List<string>();
        if (!string.IsNullOrWhiteSpace(packageName))
        {
            identities.Add(packageName.Trim());
        }

        var directory = Path.GetDirectoryName(manifestPath.Replace('/', Path.DirectorySeparatorChar));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            var normalizedDirectory = directory.Replace('\\', '/');
            identities.Add(normalizedDirectory);

            var leaf = Path.GetFileName(directory);
            if (string.IsNullOrWhiteSpace(packageName) && leaf.Length >= 4)
            {
                identities.Add(leaf);
            }
        }

        return identities
            .Where(identity => identity.Length >= 3)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(identity => identity.Length)
            .ToArray();
    }

    private static bool ContainsIdentity(string text, IReadOnlyList<string> identities) =>
        identities.Any(identity => Regex.IsMatch(
            text,
            $@"(?<![A-Za-z0-9_@/.-]){Regex.Escape(identity)}(?![A-Za-z0-9_/.-])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100)));

    private static string? FindFirstVersion(string text)
    {
        var match = SemanticVersionPattern().Match(text);
        return match.Success ? match.Groups["version"].Value : null;
    }

    [GeneratedRegex(
        @"^\s*(?<key>name|version)\s*=\s*[""'](?<value>[^""']+)[""']",
        RegexOptions.CultureInvariant)]
    private static partial Regex PyprojectPropertyPattern();

    [GeneratedRegex(
        @"^#+\s*\[?(?<version>v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\]?",
        RegexOptions.CultureInvariant)]
    private static partial Regex ChangelogHeadingPattern();

    [GeneratedRegex(
        @"^(?<level>#+)\s+(?<text>.+)$",
        RegexOptions.CultureInvariant)]
    private static partial Regex MarkdownHeadingPattern();

    [GeneratedRegex(
        @"(?<!\d)(?<version>v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?!\d)",
        RegexOptions.CultureInvariant)]
    private static partial Regex SemanticVersionPattern();
}

internal sealed record PyprojectPackage(string? Name, string? Version);

internal sealed record PackageChangelogMatch(
    bool ReferencesPackage,
    IReadOnlyList<string> Versions);

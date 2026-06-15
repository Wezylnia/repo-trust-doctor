using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Repository;

internal sealed record CargoWorkspaceDeclarations(
    bool IsWorkspace,
    IReadOnlyList<string> Members,
    IReadOnlyList<string> Excludes);

internal static class WorkspaceDeclarationParser
{
    public static IReadOnlyList<string> ReadNpmPatterns(JsonElement workspaces)
    {
        if (workspaces.ValueKind == JsonValueKind.Array)
        {
            return ReadStringArray(workspaces);
        }

        if (workspaces.ValueKind == JsonValueKind.Object &&
            workspaces.TryGetProperty("packages", out var packages) &&
            packages.ValueKind == JsonValueKind.Array)
        {
            return ReadStringArray(packages);
        }

        return [];
    }

    public static CargoWorkspaceDeclarations ReadCargoPatterns(string content)
    {
        var section = ReadTomlSection(content, "workspace");
        if (section is null)
        {
            return new CargoWorkspaceDeclarations(false, [], []);
        }

        return new CargoWorkspaceDeclarations(
            true,
            ReadTomlStringArray(section, "members"),
            ReadTomlStringArray(section, "exclude"));
    }

    public static IReadOnlyList<string> ReadGoUsePaths(string content)
    {
        var paths = new List<string>();
        var inUseBlock = false;

        foreach (var rawLine in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripGoComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (inUseBlock)
            {
                if (line == ")")
                {
                    inUseBlock = false;
                    continue;
                }

                AddGoPath(paths, line);
                continue;
            }

            if (!line.StartsWith("use", StringComparison.Ordinal) ||
                (line.Length > 3 && !char.IsWhiteSpace(line[3]) && line[3] != '('))
            {
                continue;
            }

            var value = line[3..].Trim();
            if (value == "(")
            {
                inUseBlock = true;
            }
            else if (value.StartsWith('(') && value.EndsWith(')'))
            {
                AddGoPath(paths, value[1..^1]);
            }
            else
            {
                AddGoPath(paths, value);
            }
        }

        return paths;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement array) =>
        array.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .ToArray();

    private static string? ReadTomlSection(string content, string expectedSection)
    {
        var builder = new StringBuilder();
        var foundExpectedSection = false;
        var inExpectedSection = false;

        foreach (var rawLine in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripTomlComment(rawLine).Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var section = line.Trim('[', ']', ' ');
                inExpectedSection = section.Equals(expectedSection, StringComparison.Ordinal);
                foundExpectedSection |= inExpectedSection;
                continue;
            }

            if (inExpectedSection)
            {
                builder.AppendLine(line);
            }
        }

        return foundExpectedSection ? builder.ToString() : null;
    }

    private static IReadOnlyList<string> ReadTomlStringArray(string section, string property)
    {
        var match = Regex.Match(
            section,
            $@"(?:^|\n)\s*{Regex.Escape(property)}\s*=\s*\[(?<items>.*?)\]",
            RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return [];
        }

        return Regex.Matches(match.Groups["items"].Value, @"[""'](?<value>[^""']+)[""']")
            .Select(item => item.Groups["value"].Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
    }

    private static string StripTomlComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var current = line[index];
            if (quote == '\0' && (current == '"' || current == '\''))
            {
                quote = current;
            }
            else if (quote == current && (index == 0 || line[index - 1] != '\\'))
            {
                quote = '\0';
            }
            else if (quote == '\0' && current == '#')
            {
                return line[..index];
            }
        }

        return line;
    }

    private static string StripGoComment(string line)
    {
        var comment = line.IndexOf("//", StringComparison.Ordinal);
        return comment < 0 ? line : line[..comment];
    }

    private static void AddGoPath(ICollection<string> paths, string value)
    {
        var path = value.Trim().Trim('"', '\'', '`');
        if (!string.IsNullOrWhiteSpace(path))
        {
            paths.Add(path);
        }
    }
}

internal static class WorkspaceMemberResolver
{
    public static IReadOnlyList<string> Resolve(
        string repositoryPath,
        string workspaceFilePath,
        IEnumerable<string> declarations,
        IEnumerable<string> candidateManifestPaths,
        IEnumerable<string>? excludes = null)
    {
        var patterns = declarations
            .Select(NormalizePattern)
            .Where(pattern => !pattern.StartsWith('!'))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var negativePatterns = declarations
            .Where(pattern => pattern.TrimStart().StartsWith('!'))
            .Select(pattern => NormalizePattern(pattern.TrimStart()[1..]))
            .Concat(excludes?.Select(NormalizePattern) ?? [])
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (patterns.Length == 0)
        {
            return [];
        }

        var workspaceDirectory = Path.GetDirectoryName(Path.GetFullPath(workspaceFilePath))!;
        var repositoryRoot = Path.GetFullPath(repositoryPath);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        var positiveMatchers = patterns.Select(CreateMatcher).ToArray();
        var negativeMatchers = negativePatterns.Select(CreateMatcher).ToArray();

        return candidateManifestPaths
            .Select(Path.GetFullPath)
            .Where(path => IsInsideRepository(repositoryRoot, path, comparison))
            .Select(Path.GetDirectoryName)
            .Where(path => path is not null)
            .Select(path => path!)
            .Distinct(OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal)
            .Select(directory => new
            {
                Directory = directory,
                WorkspaceRelative = NormalizePath(Path.GetRelativePath(workspaceDirectory, directory))
            })
            .Where(candidate => positiveMatchers.Any(matcher => matcher.IsMatch(candidate.WorkspaceRelative)))
            .Where(candidate => !negativeMatchers.Any(matcher => matcher.IsMatch(candidate.WorkspaceRelative)))
            .Select(candidate => NormalizePath(Path.GetRelativePath(repositoryRoot, candidate.Directory)))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
    }

    private static bool IsInsideRepository(
        string repositoryRoot,
        string candidatePath,
        StringComparison comparison)
    {
        var relative = Path.GetRelativePath(repositoryRoot, candidatePath);
        return !relative.Equals("..", comparison) &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", comparison) &&
               !Path.IsPathRooted(relative);
    }

    private static Regex CreateMatcher(string pattern)
    {
        var expression = new StringBuilder("^");
        for (var index = 0; index < pattern.Length; index++)
        {
            var current = pattern[index];
            if (current == '*' && index + 1 < pattern.Length && pattern[index + 1] == '*')
            {
                expression.Append(".*");
                index++;
            }
            else if (current == '*')
            {
                expression.Append("[^/]*");
            }
            else if (current == '?')
            {
                expression.Append("[^/]");
            }
            else
            {
                expression.Append(Regex.Escape(current.ToString()));
            }
        }

        expression.Append('$');
        var options = RegexOptions.CultureInvariant;
        if (OperatingSystem.IsWindows())
        {
            options |= RegexOptions.IgnoreCase;
        }

        return new Regex(expression.ToString(), options, TimeSpan.FromMilliseconds(100));
    }

    private static string NormalizePattern(string pattern)
    {
        var normalized = NormalizePath(pattern.Trim().Trim('"', '\'', '`'));
        while (normalized.StartsWith("./", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        if (normalized.EndsWith("/...", StringComparison.Ordinal))
        {
            normalized = normalized[..^4];
        }

        return normalized.TrimEnd('/');
    }

    private static string NormalizePath(string path)
    {
        var normalized = path.Replace('\\', '/').TrimEnd('/');
        return normalized.Length == 0 ? "." : normalized;
    }
}

using System.Text;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.ReleaseEvidence;

internal static partial class ReleaseEvidenceParsing
{
    public static string? ReadPyprojectVersion(string content)
    {
        string? section = null;
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

            var match = PyprojectVersionPattern().Match(line);
            if (match.Success)
            {
                return match.Groups["version"].Value;
            }
        }

        return null;
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

    [GeneratedRegex(
        @"^\s*version\s*=\s*[""'](?<version>[^""']+)[""']",
        RegexOptions.CultureInvariant)]
    private static partial Regex PyprojectVersionPattern();
}

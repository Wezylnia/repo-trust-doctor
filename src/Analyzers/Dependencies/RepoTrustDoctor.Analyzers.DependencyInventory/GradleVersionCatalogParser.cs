using System.Text;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed record GradleCatalogLibrary(
    string Alias,
    string Module,
    string? Version,
    string? VersionReference);

internal sealed record GradleCatalogPlugin(
    string Alias,
    string PluginId,
    string? Version,
    string? VersionReference);

internal sealed record GradleVersionCatalog(
    IReadOnlyDictionary<string, string> Versions,
    IReadOnlyList<GradleCatalogLibrary> Libraries,
    IReadOnlyList<GradleCatalogPlugin> Plugins);

internal static partial class GradleVersionCatalogParser
{
    public static GradleVersionCatalog Parse(string content)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var libraries = new List<GradleCatalogLibrary>();
        var plugins = new List<GradleCatalogPlugin>();
        string? section = null;

        foreach (var entry in ReadLogicalLines(content))
        {
            if (entry.StartsWith('[') && entry.EndsWith(']'))
            {
                section = entry.Trim('[', ']').Trim().ToLowerInvariant();
                continue;
            }

            if (!TrySplitAssignment(entry, out var alias, out var value))
            {
                continue;
            }

            switch (section)
            {
                case "versions" when TryReadQuotedValue(value, out var version):
                    versions[alias] = version;
                    break;
                case "libraries" when TryParseLibrary(alias, value, out var library):
                    libraries.Add(library);
                    break;
                case "plugins" when TryParsePlugin(alias, value, out var plugin):
                    plugins.Add(plugin);
                    break;
            }
        }

        return new GradleVersionCatalog(versions, libraries, plugins);
    }

    private static IEnumerable<string> ReadLogicalLines(string content)
    {
        var builder = new StringBuilder();
        var braceDepth = 0;
        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = StripComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(' ');
            }
            builder.Append(line);
            braceDepth += CountOutsideQuotes(line, '{') - CountOutsideQuotes(line, '}');
            if (braceDepth > 0)
            {
                continue;
            }

            yield return builder.ToString();
            builder.Clear();
            braceDepth = 0;
        }

        if (builder.Length > 0)
        {
            yield return builder.ToString();
        }
    }

    private static bool TryParseLibrary(
        string alias,
        string value,
        out GradleCatalogLibrary library)
    {
        library = default!;
        if (TryReadQuotedValue(value, out var coordinates))
        {
            var parts = coordinates.Split(':', 3, StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
            {
                return false;
            }

            library = new GradleCatalogLibrary(
                alias,
                $"{parts[0]}:{parts[1]}",
                parts.Length == 3 ? parts[2] : null,
                null);
            return true;
        }

        if (!value.StartsWith('{') ||
            !TryReadInlineString(value, "module", out var module))
        {
            if (!TryReadInlineString(value, "group", out var group) ||
                !TryReadInlineString(value, "name", out var name))
            {
                return false;
            }

            module = $"{group}:{name}";
        }

        TryReadInlineString(value, "version", out var version);
        if (version.Length == 0)
        {
            version = ReadRichVersion(value) ?? string.Empty;
        }
        var versionReference = ReadVersionReference(value);
        library = new GradleCatalogLibrary(
            alias,
            module,
            version.Length == 0 ? null : version,
            versionReference);
        return true;
    }

    private static bool TryParsePlugin(
        string alias,
        string value,
        out GradleCatalogPlugin plugin)
    {
        plugin = default!;
        if (!TryReadInlineString(value, "id", out var pluginId))
        {
            return false;
        }

        TryReadInlineString(value, "version", out var version);
        plugin = new GradleCatalogPlugin(alias, pluginId, version, ReadVersionReference(value));
        return true;
    }

    private static string? ReadVersionReference(string value)
    {
        if (TryReadInlineString(value, "version.ref", out var directReference))
        {
            return directReference;
        }

        var match = NestedVersionReferencePattern().Match(value);
        return match.Success ? match.Groups["value"].Value : null;
    }

    private static string? ReadRichVersion(string value)
    {
        var match = RichVersionPattern().Match(value);
        return match.Success ? match.Groups["value"].Value : null;
    }

    private static bool TryReadInlineString(string value, string key, out string result)
    {
        var match = Regex.Match(
            value,
            $@"(?:^|[,{{]\s*){Regex.Escape(key)}\s*=\s*[""'](?<value>[^""']+)[""']",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        result = match.Success ? match.Groups["value"].Value : string.Empty;
        return match.Success;
    }

    private static bool TrySplitAssignment(
        string line,
        out string key,
        out string value)
    {
        key = string.Empty;
        value = string.Empty;
        var equalsIndex = FindOutsideQuotes(line, '=');
        if (equalsIndex <= 0)
        {
            return false;
        }

        key = line[..equalsIndex].Trim().Trim('"', '\'');
        value = line[(equalsIndex + 1)..].Trim();
        return key.Length > 0 && value.Length > 0;
    }

    private static bool TryReadQuotedValue(string value, out string result)
    {
        result = string.Empty;
        var trimmed = value.Trim();
        if (trimmed.Length < 2 ||
            trimmed[0] is not ('"' or '\'') ||
            trimmed[^1] != trimmed[0])
        {
            return false;
        }

        result = trimmed[1..^1];
        return true;
    }

    private static string StripComment(string line)
    {
        var index = FindOutsideQuotes(line, '#');
        return index < 0 ? line : line[..index];
    }

    private static int CountOutsideQuotes(string value, char target)
    {
        var count = 0;
        var quote = '\0';
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (quote == '\0' && character is '"' or '\'')
            {
                quote = character;
            }
            else if (character == quote && (index == 0 || value[index - 1] != '\\'))
            {
                quote = '\0';
            }
            else if (quote == '\0' && character == target)
            {
                count++;
            }
        }

        return count;
    }

    private static int FindOutsideQuotes(string value, char target)
    {
        var quote = '\0';
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (quote == '\0' && character is '"' or '\'')
            {
                quote = character;
            }
            else if (character == quote && (index == 0 || value[index - 1] != '\\'))
            {
                quote = '\0';
            }
            else if (quote == '\0' && character == target)
            {
                return index;
            }
        }

        return -1;
    }

    [GeneratedRegex(
        @"version\s*=\s*\{\s*ref\s*=\s*[""'](?<value>[^""']+)[""']\s*\}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NestedVersionReferencePattern();

    [GeneratedRegex(
        @"version\s*=\s*\{[^}]*\b(?:strictly|require|prefer)\s*=\s*[""'](?<value>[^""']+)[""'][^}]*\}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RichVersionPattern();
}

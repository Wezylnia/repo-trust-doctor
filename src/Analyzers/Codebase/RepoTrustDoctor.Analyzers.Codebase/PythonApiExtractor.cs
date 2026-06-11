using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

/// <summary>
/// Extracts public API symbols from Python files.
/// </summary>
internal static partial class PythonApiExtractor
{
    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        // Check if there is an explicit __all__ definition
        var allMatch = AllRegex().Match(source);
        if (allMatch.Success)
        {
            var content = allMatch.Groups["content"].Value;
            var symbolMatches = SymbolLiteralRegex().Matches(content);
            foreach (Match match in symbolMatches)
            {
                var sym = match.Groups["sym"].Value;
                if (!string.IsNullOrWhiteSpace(sym))
                {
                    symbols.Add(sym);
                }
            }
            if (symbols.Count > 0)
            {
                return symbols.ToArray();
            }
        }

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var classMatch = ClassRegex().Match(line);
            if (classMatch.Success)
            {
                var name = classMatch.Groups["name"].Value;
                if (!name.StartsWith('_'))
                {
                    symbols.Add($"class {name}");
                }
                continue;
            }

            var defMatch = DefRegex().Match(line);
            if (defMatch.Success)
            {
                var name = defMatch.Groups["name"].Value;
                if (!name.StartsWith('_'))
                {
                    symbols.Add($"def {name}");
                }
            }
        }

        return symbols.ToArray();
    }

    [GeneratedRegex(@"__all__\s*=\s*\[(?<content>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex AllRegex();

    [GeneratedRegex(@"['""](?<sym>[A-Za-z_]\w*)['""]")]
    private static partial Regex SymbolLiteralRegex();

    [GeneratedRegex(@"^class\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex ClassRegex();

    [GeneratedRegex(@"^def\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex DefRegex();
}

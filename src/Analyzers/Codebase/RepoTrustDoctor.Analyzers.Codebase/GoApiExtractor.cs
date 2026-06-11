using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

/// <summary>
/// Extracts exported public API symbols from Go source files.
/// Exported symbols in Go start with an uppercase letter.
/// </summary>
internal static partial class GoApiExtractor
{
    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        
        string? packageName = null;

        // First pass: find package declaration
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.StartsWith("package ", StringComparison.Ordinal))
            {
                var match = PackageRegex().Match(line);
                if (match.Success)
                {
                    packageName = match.Groups["package"].Value;
                    break;
                }
            }
        }

        var prefix = string.IsNullOrEmpty(packageName) ? "" : $"{packageName}.";

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("/*", StringComparison.Ordinal))
            {
                continue;
            }

            // Exported function: func ExportedName(...)
            var funcMatch = FuncRegex().Match(line);
            if (funcMatch.Success)
            {
                var name = funcMatch.Groups["name"].Value;
                if (char.IsUpper(name[0]))
                {
                    symbols.Add($"func {prefix}{name}");
                }
                continue;
            }

            // Exported type: type ExportedName ...
            var typeMatch = TypeRegex().Match(line);
            if (typeMatch.Success)
            {
                var name = typeMatch.Groups["name"].Value;
                if (char.IsUpper(name[0]))
                {
                    symbols.Add($"type {prefix}{name}");
                }
                continue;
            }

            // Exported const/var at package level: const ExportedName = ... or var ExportedName = ...
            var varConstMatch = VarConstRegex().Match(line);
            if (varConstMatch.Success)
            {
                var kind = varConstMatch.Groups["kind"].Value;
                var name = varConstMatch.Groups["name"].Value;
                if (char.IsUpper(name[0]))
                {
                    symbols.Add($"{kind} {prefix}{name}");
                }
            }
        }

        return symbols.ToArray();
    }

    [GeneratedRegex(@"^package\s+(?<package>[A-Za-z_]\w*)\b")]
    private static partial Regex PackageRegex();

    [GeneratedRegex(@"^func\s+(?:\([^)]+\)\s*)?(?<name>[A-Za-z_]\w*)\s*\(")]
    private static partial Regex FuncRegex();

    [GeneratedRegex(@"^type\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex TypeRegex();

    [GeneratedRegex(@"^(?<kind>var|const)\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex VarConstRegex();
}

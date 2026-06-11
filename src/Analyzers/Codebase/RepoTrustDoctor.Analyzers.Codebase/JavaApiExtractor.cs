using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

/// <summary>
/// Extracts public API symbols from Java files.
/// </summary>
internal static partial class JavaApiExtractor
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
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("*", StringComparison.Ordinal))
            {
                continue;
            }

            // Match public class/interface/enum/record
            var typeMatch = TypeRegex().Match(line);
            if (typeMatch.Success)
            {
                var kind = typeMatch.Groups["kind"].Value;
                var name = typeMatch.Groups["name"].Value;
                symbols.Add($"public {kind} {prefix}{name}");
                continue;
            }

            // Match public static methods or constants (often seen in public APIs)
            var staticMatch = PublicStaticRegex().Match(line);
            if (staticMatch.Success)
            {
                var name = staticMatch.Groups["name"].Value;
                symbols.Add($"public static {prefix}{name}");
            }
        }

        return symbols.ToArray();
    }

    [GeneratedRegex(@"^package\s+(?<package>[A-Za-z_][\w.]*)\s*;")]
    private static partial Regex PackageRegex();

    [GeneratedRegex(@"^\s*public\s+(?<kind>class|interface|enum|record)\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex TypeRegex();

    [GeneratedRegex(@"^\s*public\s+static\s+(?:[\w<>[\]?]+)\s+(?<name>[A-Za-z_]\w*)\s*\(")]
    private static partial Regex PublicStaticRegex();
}

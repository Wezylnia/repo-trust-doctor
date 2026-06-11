using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

/// <summary>
/// Extracts exported public API symbols from TypeScript and JavaScript source files.
/// Detects: export class, export function, export const, export interface, export type, export enum, export default.
/// </summary>
internal static partial class TypeScriptApiExtractor
{
    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var rawLine in source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("*", StringComparison.Ordinal))
            {
                continue;
            }

            var namedExport = NamedExportRegex().Match(line);
            if (namedExport.Success)
            {
                var kind = namedExport.Groups["kind"].Value;
                var name = namedExport.Groups["name"].Value;
                symbols.Add($"export {kind} {name}");
                continue;
            }

            var constExport = ConstExportRegex().Match(line);
            if (constExport.Success)
            {
                var name = constExport.Groups["name"].Value;
                symbols.Add($"export const {name}");
                continue;
            }

            var letExport = LetExportRegex().Match(line);
            if (letExport.Success)
            {
                var name = letExport.Groups["name"].Value;
                symbols.Add($"export let {name}");
                continue;
            }

            var defaultExport = DefaultExportRegex().Match(line);
            if (defaultExport.Success)
            {
                symbols.Add("export default");
            }
        }

        return symbols.ToArray();
    }

    [GeneratedRegex(@"^\s*export\s+(?:declare\s+)?(?:abstract\s+)?(?<kind>class|function|interface|type|enum)\s+(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")]
    private static partial Regex NamedExportRegex();

    [GeneratedRegex(@"^\s*export\s+(?:declare\s+)?const\s+(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")]
    private static partial Regex ConstExportRegex();

    [GeneratedRegex(@"^\s*export\s+(?:declare\s+)?let\s+(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")]
    private static partial Regex LetExportRegex();

    [GeneratedRegex(@"^\s*export\s+default\b")]
    private static partial Regex DefaultExportRegex();
}

using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

/// <summary>
/// Extracts public API symbols from Rust source files.
/// Detects 'pub' declarations (excluding pub(crate), pub(super), etc.).
/// </summary>
internal static partial class RustApiExtractor
{
    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("/*", StringComparison.Ordinal))
            {
                continue;
            }

            // Match pub fn, pub struct, pub enum, pub trait, pub type, pub const, pub static, pub mod
            // Ensure we don't match pub(crate), pub(super), pub(self), pub(in ...)
            var pubMatch = RustPubRegex().Match(line);
            if (pubMatch.Success)
            {
                var kind = pubMatch.Groups["kind"].Value;
                var name = pubMatch.Groups["name"].Value;
                symbols.Add($"pub {kind} {name}");
            }
        }

        return symbols.ToArray();
    }

    [GeneratedRegex(@"^\bpub\s+(?!fn\s+macro_rules)(?<kind>fn|struct|enum|trait|type|const|static|mod)\s+(?<name>[A-Za-z_]\w*)\b")]
    private static partial Regex RustPubRegex();
}

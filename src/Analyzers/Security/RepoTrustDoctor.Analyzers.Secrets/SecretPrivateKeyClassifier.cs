using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.Secrets;

internal static class SecretPrivateKeyClassifier
{
    public static bool ShouldSuppress(
        string relativePath,
        string content,
        Match markerMatch,
        Match blockMatch)
    {
        if (IsDocumentationTextPath(relativePath) &&
            IsLikelyDocumentationExample(blockMatch.Success ? blockMatch.Value : markerMatch.Value))
        {
            return true;
        }

        return blockMatch.Success
            ? IsLikelySourceCodePattern(relativePath, blockMatch)
            : IsLikelySourceCodeMarker(relativePath, content, markerMatch.Index);
    }

    private static bool IsDocumentationTextPath(string relativePath)
    {
        var normalized = RepositoryPathClassifier.Normalize(relativePath);
        var isDocumentationFile = normalized.EndsWith(".md", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".adoc", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".rst", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".txt", StringComparison.OrdinalIgnoreCase);

        return isDocumentationFile && RepositoryPathClassifier.IsDocumentationPath(normalized);
    }

    private static bool IsLikelyDocumentationExample(string matchedText)
    {
        var lower = matchedText.ToLowerInvariant();
        if (lower.Contains("example", StringComparison.Ordinal) ||
            lower.Contains("sample", StringComparison.Ordinal) ||
            lower.Contains("documentation", StringComparison.Ordinal) ||
            lower.Contains("placeholder", StringComparison.Ordinal) ||
            lower.Contains("dummy", StringComparison.Ordinal) ||
            lower.Contains("fake", StringComparison.Ordinal) ||
            lower.Contains("redacted", StringComparison.Ordinal) ||
            lower.Contains("your private key", StringComparison.Ordinal) ||
            lower.Contains("...", StringComparison.Ordinal))
        {
            return true;
        }

        return !HasBase64Material(matchedText);
    }

    private static bool HasBase64Material(string matchedText)
    {
        foreach (var line in matchedText
                     .Replace("\r\n", "\n", StringComparison.Ordinal)
                     .Replace('\r', '\n')
                     .Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length < 40 ||
                trimmed.StartsWith("-----", StringComparison.Ordinal) ||
                trimmed.Contains(':', StringComparison.Ordinal))
            {
                continue;
            }

            if (trimmed.All(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is '+' or '/' or '='))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLikelySourceCodeMarker(
        string relativePath,
        string content,
        int matchIndex)
    {
        if (!IsSourceCodePath(relativePath))
        {
            return false;
        }

        var lineStart = content.LastIndexOf('\n', Math.Max(0, matchIndex - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var lineEnd = content.IndexOf('\n', matchIndex);
        lineEnd = lineEnd < 0 ? content.Length : lineEnd;
        var line = content[lineStart..lineEnd].Trim();

        return line.StartsWith("//", StringComparison.Ordinal) ||
               line.StartsWith("#", StringComparison.Ordinal) ||
               line.StartsWith("*", StringComparison.Ordinal) ||
               line.Contains('"', StringComparison.Ordinal) ||
               line.Contains('\'', StringComparison.Ordinal) ||
               line.Contains('`', StringComparison.Ordinal);
    }

    private static bool IsLikelySourceCodePattern(
        string relativePath,
        Match match)
    {
        if (!IsSourceCodePath(relativePath))
        {
            return false;
        }

        var matchedText = match.Value;
        return matchedText.Contains(@"[\s\S]", StringComparison.Ordinal) ||
               matchedText.Contains(@"\s", StringComparison.Ordinal) ||
               matchedText.Contains(".+?", StringComparison.Ordinal) ||
               matchedText.Contains(".*?", StringComparison.Ordinal);
    }

    private static bool IsSourceCodePath(string relativePath)
    {
        var extension = Path.GetExtension(relativePath);
        return extension.Equals(".cs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ts", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".tsx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".jsx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".java", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".go", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".py", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".rs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".kt", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".swift", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".php", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".rb", StringComparison.OrdinalIgnoreCase);
    }
}

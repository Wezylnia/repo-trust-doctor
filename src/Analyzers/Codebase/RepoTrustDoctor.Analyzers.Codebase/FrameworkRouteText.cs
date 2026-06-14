using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Codebase;

internal static partial class FrameworkRouteText
{
    private const int MaxRouteStatementLength = 1200;

    internal static int CountLineNumber(string text, int charIndex)
    {
        var line = 1;
        for (var index = 0; index < charIndex && index < text.Length; index++)
        {
            if (text[index] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    internal static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : string.Concat(value.AsSpan(0, maxLength - 3), "...");

    internal static string ExtractRouteSnippet(string text, Match routeMatch)
    {
        var value = routeMatch.Value.Trim();
        return value.EndsWith('(')
            ? NormalizeRouteSnippet(GetRouteStatement(text, routeMatch))
            : value;
    }

    internal static bool IsLikelyNonCodeRouteMatch(string text, int index)
    {
        var lineStart = text.LastIndexOf('\n', Math.Max(0, index - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var linePrefix = text[lineStart..index];

        if (linePrefix.Contains("//", StringComparison.Ordinal) ||
            linePrefix.Contains('#', StringComparison.Ordinal) ||
            IsInsideQuotedText(linePrefix))
        {
            return true;
        }

        var prefix = text[..index];
        var lastBlockOpen = prefix.LastIndexOf("/*", StringComparison.Ordinal);
        if (lastBlockOpen >= 0)
        {
            var lastBlockClose = prefix.LastIndexOf("*/", StringComparison.Ordinal);
            return lastBlockClose < lastBlockOpen;
        }

        return false;
    }

    internal static string GetRouteStatement(string text, Match routeMatch)
    {
        var maxEnd = Math.Min(text.Length, routeMatch.Index + MaxRouteStatementLength);
        var end = FindStatementEnd(text, routeMatch.Index, maxEnd);
        if (end < 0)
        {
            var newline = text.IndexOf('\n', routeMatch.Index, maxEnd - routeMatch.Index);
            end = newline >= 0 ? newline : maxEnd - 1;
        }

        var length = Math.Min(end - routeMatch.Index + 1, text.Length - routeMatch.Index);
        return length <= 0 ? string.Empty : text.Substring(routeMatch.Index, length);
    }

    private static bool IsInsideQuotedText(string text)
    {
        var single = false;
        var doubleQuote = false;
        var backtick = false;
        var escaped = false;

        foreach (var current in text)
        {
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (current == '\\')
            {
                escaped = true;
                continue;
            }

            if (current == '\'' && !doubleQuote && !backtick)
            {
                single = !single;
            }
            else if (current == '"' && !single && !backtick)
            {
                doubleQuote = !doubleQuote;
            }
            else if (current == '`' && !single && !doubleQuote)
            {
                backtick = !backtick;
            }
        }

        return single || doubleQuote || backtick;
    }

    private static string NormalizeRouteSnippet(string value) =>
        WhitespaceRegex().Replace(value.Trim(), " ");

    private static int FindStatementEnd(string text, int start, int maxEnd)
    {
        var parenDepth = 0;
        var braceDepth = 0;
        var bracketDepth = 0;
        var inString = false;
        var stringDelimiter = '\0';
        var escaped = false;

        for (var index = start; index < maxEnd; index++)
        {
            var current = text[index];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (current == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (current == stringDelimiter)
                {
                    inString = false;
                }

                continue;
            }

            if (current is '"' or '\'' or '`')
            {
                inString = true;
                stringDelimiter = current;
                continue;
            }

            switch (current)
            {
                case '(':
                    parenDepth++;
                    break;
                case ')':
                    parenDepth = Math.Max(0, parenDepth - 1);
                    break;
                case '{':
                    braceDepth++;
                    break;
                case '}':
                    braceDepth = Math.Max(0, braceDepth - 1);
                    break;
                case '[':
                    bracketDepth++;
                    break;
                case ']':
                    bracketDepth = Math.Max(0, bracketDepth - 1);
                    break;
                case ';' when parenDepth == 0 && braceDepth == 0 && bracketDepth == 0:
                    return index;
            }
        }

        return -1;
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();
}

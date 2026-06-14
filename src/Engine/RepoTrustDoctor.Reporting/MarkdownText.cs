using System.Text;

namespace RepoTrustDoctor.Reporting;

internal static class MarkdownText
{
    public static string Inline(string? value)
    {
        var text = NormalizeInline(value);
        if (text.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            switch (c)
            {
                case '\\':
                case '`':
                case '*':
                case '_':
                case '{':
                case '}':
                case '[':
                case ']':
                case '(':
                case ')':
                case '#':
                case '+':
                case '!':
                case '|':
                    builder.Append('\\');
                    builder.Append(c);
                    break;
                case '&':
                    builder.Append("&amp;");
                    break;
                case '<':
                    builder.Append("&lt;");
                    break;
                case '>':
                    builder.Append("&gt;");
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        return builder.ToString();
    }

    public static string Heading(string? value) => Inline(value);

    public static string TableCell(string? value) => Inline(value);

    public static string Code(string? value)
    {
        var text = NormalizeInline(value);
        var delimiter = new string('`', LongestBacktickRun(text) + 1);
        var padding = text.StartsWith('`') || text.EndsWith('`') ? " " : string.Empty;

        return $"{delimiter}{padding}{text}{padding}{delimiter}";
    }

    private static string NormalizeInline(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        var previousWasSpace = false;
        foreach (var c in value)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c))
            {
                if (!previousWasSpace)
                {
                    builder.Append(' ');
                    previousWasSpace = true;
                }

                continue;
            }

            builder.Append(c);
            previousWasSpace = false;
        }

        return builder.ToString().Trim();
    }

    private static int LongestBacktickRun(string text)
    {
        var longest = 0;
        var current = 0;
        foreach (var c in text)
        {
            if (c == '`')
            {
                current++;
                longest = Math.Max(longest, current);
            }
            else
            {
                current = 0;
            }
        }

        return longest;
    }
}

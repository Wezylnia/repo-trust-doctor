using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Terraform;

internal sealed record TerraformBlock(
    string Header,
    IReadOnlyList<string> Labels,
    string Text,
    int StartLine);

internal static partial class TerraformBlockExtractor
{
    public static IReadOnlyList<TerraformBlock> Extract(string content) =>
        ExtractBlocks(content, @"(?m)^\s*(?<header>(?<type>resource|data|terraform|backend|required_providers|provider|module|locals|variable|output)\b[^{]*)\{");

    public static IReadOnlyList<TerraformBlock> ExtractAssignments(string content, int baseLine) =>
        ExtractBlocks(content, @"(?m)^\s*(?<header>[A-Za-z0-9_-]+\s*=)\s*\{", baseLine - 1);

    public static IReadOnlyList<string> ExtractBraceChunks(string content)
    {
        var chunks = new List<string>();
        for (var index = 0; index < content.Length; index++)
        {
            if (content[index] != '{')
            {
                continue;
            }

            var end = FindMatchingBrace(content, index);
            if (end > index)
            {
                chunks.Add(content[index..(end + 1)]);
                index = end;
            }
        }

        return chunks;
    }

    private static IReadOnlyList<TerraformBlock> ExtractBlocks(
        string content,
        string pattern,
        int lineOffset = 0)
    {
        var blocks = new List<TerraformBlock>();
        foreach (Match match in Regex.Matches(content, pattern, RegexOptions.IgnoreCase))
        {
            var openBrace = content.IndexOf('{', match.Index);
            if (openBrace < 0)
            {
                continue;
            }

            var closeBrace = FindMatchingBrace(content, openBrace);
            if (closeBrace <= openBrace)
            {
                continue;
            }

            var header = match.Groups["header"].Value.Trim();
            blocks.Add(new TerraformBlock(
                header,
                LabelPattern().Matches(header).Select(label => label.Groups["label"].Value).ToArray(),
                content[match.Index..(closeBrace + 1)],
                lineOffset + GetLineNumber(content, match.Index)));
        }

        return blocks;
    }

    private static int FindMatchingBrace(string content, int openBrace)
    {
        var depth = 0;
        var inString = false;
        var escaped = false;
        var inLineComment = false;
        var inBlockComment = false;
        string? heredocTerminator = null;
        var atLineStart = true;

        for (var index = openBrace; index < content.Length; index++)
        {
            var current = content[index];
            var next = index + 1 < content.Length ? content[index + 1] : '\0';

            if (heredocTerminator is not null)
            {
                if (atLineStart && IsHeredocTerminatorAt(content, index, heredocTerminator))
                {
                    heredocTerminator = null;
                }

                atLineStart = current == '\n';
                continue;
            }

            if (inLineComment)
            {
                if (current == '\n')
                {
                    inLineComment = false;
                    atLineStart = true;
                }

                continue;
            }

            if (inBlockComment)
            {
                if (current == '*' && next == '/')
                {
                    inBlockComment = false;
                    index++;
                    continue;
                }

                atLineStart = current == '\n';
                continue;
            }

            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (current == '\\')
                {
                    escaped = true;
                }
                else if (current == '"')
                {
                    inString = false;
                }

                atLineStart = current == '\n';
                continue;
            }

            if (current == '"')
            {
                inString = true;
                atLineStart = false;
                continue;
            }

            if (current == '/' && next == '*')
            {
                inBlockComment = true;
                index++;
                continue;
            }

            if (current == '#' || (current == '/' && next == '/'))
            {
                inLineComment = true;
                if (current == '/')
                {
                    index++;
                }

                continue;
            }

            if (current == '<' && next == '<' && TryReadHeredocTerminator(content, index, out var terminator))
            {
                heredocTerminator = terminator;
            }

            if (current == '{')
            {
                depth++;
            }
            else if (current == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }

            atLineStart = current == '\n';
        }

        return -1;
    }

    private static bool TryReadHeredocTerminator(string content, int markerIndex, out string terminator)
    {
        terminator = string.Empty;
        var index = markerIndex + 2;
        if (index < content.Length && content[index] == '-')
        {
            index++;
        }

        while (index < content.Length && char.IsWhiteSpace(content[index]) && content[index] != '\n')
        {
            index++;
        }

        var start = index;
        while (index < content.Length && (char.IsLetterOrDigit(content[index]) || content[index] == '_'))
        {
            index++;
        }

        if (index == start)
        {
            return false;
        }

        terminator = content[start..index];
        return true;
    }

    private static bool IsHeredocTerminatorAt(string content, int index, string terminator)
    {
        var cursor = index;
        while (cursor < content.Length && (content[cursor] == ' ' || content[cursor] == '\t'))
        {
            cursor++;
        }

        if (!content.AsSpan(cursor).StartsWith(terminator, StringComparison.Ordinal))
        {
            return false;
        }

        cursor += terminator.Length;
        return cursor >= content.Length ||
               content[cursor] == '\r' ||
               content[cursor] == '\n';
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    [GeneratedRegex("\"(?<label>[^\"]+)\"")]
    private static partial Regex LabelPattern();
}

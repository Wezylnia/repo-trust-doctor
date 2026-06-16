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
        ExtractBlocks(content, @"(?m)^\s*(?<header>(?<type>resource|data|terraform|required_providers|provider|module|locals|variable|output)\b[^{]*)\{");

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
        for (var index = openBrace; index < content.Length; index++)
        {
            if (content[index] == '{')
            {
                depth++;
            }
            else if (content[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
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

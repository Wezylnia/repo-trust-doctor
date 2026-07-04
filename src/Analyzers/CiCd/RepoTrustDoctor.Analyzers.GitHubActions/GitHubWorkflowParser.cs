namespace RepoTrustDoctor.Analyzers.GitHubActions;

internal static class GitHubWorkflowParser
{
    private const int MaxLogicalLines = 2000;

    public static GitHubWorkflowParseResult Parse(string content)
    {
        try
        {
            return ParseInternal(content);
        }
        catch (Exception ex)
        {
            return new GitHubWorkflowParseResult(
                null,
                [$"GitHub Actions workflow parser could not safely analyze this file: {ex.GetType().Name}."]);
        }
    }

    private static GitHubWorkflowParseResult ParseInternal(string content)
    {
        var warnings = new List<string>();
        var lines = SplitLines(content);
        if (lines.Length > MaxLogicalLines)
        {
            return new GitHubWorkflowParseResult(
                null,
                [$"GitHub Actions workflow parser skipped an oversized workflow ({lines.Length} logical lines)."]);
        }

        var jobsIndex = FindTopLevelKey(lines, "jobs");
        var workflowPermissions = ParseDirectMapping(
            lines,
            "permissions",
            parentIndent: -1,
            start: 0,
            end: jobsIndex >= 0 ? jobsIndex : lines.Length);
        var jobs = ParseJobs(lines, jobsIndex, warnings);

        if (jobsIndex >= 0 && jobs.Count == 0)
        {
            warnings.Add("GitHub Actions workflow parser could not identify any valid jobs under the jobs block.");
        }

        return new GitHubWorkflowParseResult(
            new GitHubWorkflowModel(ParseTriggers(lines), jobs, workflowPermissions),
            warnings);
    }

    private static IReadOnlySet<string> ParseTriggers(string[] lines)
    {
        var triggers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var onIndex = FindTopLevelKey(lines, "on");
        if (onIndex < 0)
        {
            return triggers;
        }

        var inlineValue = TryGetLineValue(lines[onIndex], "on", allowSequencePrefix: false);
        if (!string.IsNullOrWhiteSpace(inlineValue))
        {
            foreach (var trigger in ParseInlineListOrScalar(inlineValue))
            {
                triggers.Add(trigger);
            }

            return triggers;
        }

        var onIndent = GetIndentation(lines[onIndex]);
        for (var i = onIndex + 1; i < lines.Length; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= onIndent)
            {
                break;
            }

            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith("-", StringComparison.Ordinal))
            {
                var trigger = trimmed[1..].Trim().Trim('"', '\'');
                if (trigger.Length > 0)
                {
                    triggers.Add(trigger);
                }

                continue;
            }

            var colonIndex = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (colonIndex > 0)
            {
                triggers.Add(trimmed[..colonIndex].Trim());
            }
        }

        return triggers;
    }

    private static IReadOnlyDictionary<string, GitHubJobModel> ParseJobs(
        string[] lines,
        int jobsIndex,
        List<string> warnings)
    {
        var jobs = new Dictionary<string, GitHubJobModel>(StringComparer.OrdinalIgnoreCase);
        if (jobsIndex < 0)
        {
            return jobs;
        }

        var jobsIndent = GetIndentation(lines[jobsIndex]);
        var jobEntryIndent = FindFirstChildIndent(lines, jobsIndex, jobsIndent, lines.Length);
        if (jobEntryIndent is null)
        {
            return jobs;
        }

        for (var i = jobsIndex + 1; i < lines.Length; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= jobsIndent)
            {
                break;
            }

            if (indent != jobEntryIndent.Value)
            {
                continue;
            }

            var jobName = ParseKeyName(lines[i]);
            if (jobName.Length == 0)
            {
                warnings.Add($"GitHub Actions workflow parser skipped an unrecognized job entry near line {i + 1}.");
                continue;
            }

            var jobEnd = FindBlockEnd(lines, i, jobEntryIndent.Value, lines.Length);
            jobs[jobName] = ParseJob(lines, i, jobEnd, jobName);
            i = jobEnd - 1;
        }

        return jobs;
    }

    private static GitHubJobModel ParseJob(string[] lines, int start, int end, string jobName)
    {
        return new GitHubJobModel(
            jobName,
            ParseNeedsList(lines, start, end),
            ParseDirectScalar(lines, "if", start, end),
            ParseDirectBool(lines, "continue-on-error", start, end),
            ParseDirectMapping(lines, "permissions", GetIndentation(lines[start]), start, end),
            ParseSteps(lines, start, end),
            ParseDirectScalar(lines, "uses", start, end),
            start + 1);
    }

    private static IReadOnlyList<GitHubStepModel> ParseSteps(string[] lines, int jobStart, int jobEnd)
    {
        var parentIndent = GetIndentation(lines[jobStart]);
        var stepsIndex = FindDirectChildKey(lines, "steps", parentIndent, jobStart, jobEnd);
        if (stepsIndex < 0)
        {
            return [];
        }

        var stepsIndent = GetIndentation(lines[stepsIndex]);
        var stepEntryIndent = FindFirstChildIndent(lines, stepsIndex, stepsIndent, jobEnd);
        if (stepEntryIndent is null)
        {
            return [];
        }

        var steps = new List<GitHubStepModel>();
        for (var i = stepsIndex + 1; i < jobEnd; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= stepsIndent)
            {
                break;
            }

            if (indent != stepEntryIndent.Value || !lines[i].TrimStart().StartsWith("-", StringComparison.Ordinal))
            {
                continue;
            }

            var stepEnd = FindBlockEnd(lines, i, stepEntryIndent.Value, jobEnd);
            steps.Add(ParseStep(lines, i, stepEnd));
            i = stepEnd - 1;
        }

        return steps;
    }

    private static GitHubStepModel ParseStep(string[] lines, int start, int end)
    {
        return new GitHubStepModel(
            ParseDirectScalar(lines, "name", start, end, allowSequencePrefix: true),
            ParseDirectScalar(lines, "uses", start, end, allowSequencePrefix: true),
            ParseDirectScalar(lines, "run", start, end, allowSequencePrefix: true, allowMultiline: true),
            ParseDirectBool(lines, "continue-on-error", start, end, allowSequencePrefix: true),
            ParseDirectMapping(lines, "with", GetIndentation(lines[start]), start, end, allowSequencePrefix: true),
            start + 1);
    }

    private static IReadOnlyDictionary<string, string> ParseDirectMapping(
        string[] lines,
        string key,
        int parentIndent,
        int start,
        int end,
        bool allowSequencePrefix = false)
    {
        var keyIndex = parentIndent < 0
            ? FindTopLevelKey(lines, key, start, end)
            : FindDirectChildKey(lines, key, parentIndent, start, end, allowSequencePrefix);
        if (keyIndex < 0)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var baseIndent = GetIndentation(lines[keyIndex]);

        // Check for inline flow mapping: permissions: { contents: write, packages: read }
        var flowValues = TryParseFlowMapping(lines[keyIndex], key);
        if (flowValues is not null)
        {
            return flowValues;
        }

        var valueIndent = FindFirstChildIndent(lines, keyIndex, baseIndent, end);
        if (valueIndent is null)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = keyIndex + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= baseIndent)
            {
                break;
            }

            if (indent != valueIndent.Value)
            {
                continue;
            }

            var entryKey = ParseKeyName(lines[i]);
            if (entryKey.Length == 0)
            {
                continue;
            }

            var entryValue = TryGetLineValue(lines[i], entryKey, allowSequencePrefix: false) ?? string.Empty;
            if (entryValue is "|" or ">" or "|-" or ">-")
            {
                entryValue = ParseMultilineValue(lines, i, indent, end);
            }
            else if (string.IsNullOrWhiteSpace(entryValue))
            {
                entryValue = ParseIndentedList(lines, i, indent, end);
            }

            values[entryKey] = entryValue.Trim();
        }

        return values;
    }

    private static IReadOnlyList<string> ParseNeedsList(string[] lines, int start, int end)
    {
        var needsIndex = FindDirectChildKey(lines, "needs", GetIndentation(lines[start]), start, end);
        if (needsIndex < 0)
        {
            return [];
        }

        var inlineValue = TryGetLineValue(lines[needsIndex], "needs", allowSequencePrefix: false);
        if (!string.IsNullOrWhiteSpace(inlineValue))
        {
            return ParseInlineListOrScalar(inlineValue);
        }

        return ParseIndentedList(lines, needsIndex, GetIndentation(lines[needsIndex]), end)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(item => item.Trim('"', '\''))
            .Where(item => item.Length > 0)
            .ToArray();
    }

    private static string? ParseDirectScalar(
        string[] lines,
        string key,
        int start,
        int end,
        bool allowSequencePrefix = false,
        bool allowMultiline = false)
    {
        if (allowSequencePrefix)
        {
            var currentLineValue = TryGetLineValue(lines[start], key, allowSequencePrefix: true);
            if (!string.IsNullOrWhiteSpace(currentLineValue))
            {
                if (allowMultiline && currentLineValue is "|" or ">" or "|-" or ">-")
                {
                    return ParseMultilineValue(lines, start, GetIndentation(lines[start]), end);
                }

                currentLineValue = currentLineValue.Trim().Trim('"', '\'');
                return currentLineValue.Length == 0 ? null : currentLineValue;
            }
        }

        var keyIndex = FindDirectChildKey(lines, key, GetIndentation(lines[start]), start, end, allowSequencePrefix);
        if (keyIndex < 0)
        {
            return null;
        }

        var value = TryGetLineValue(lines[keyIndex], key, allowSequencePrefix);
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (allowMultiline && value is "|" or ">" or "|-" or ">-")
        {
            return ParseMultilineValue(lines, keyIndex, GetIndentation(lines[keyIndex]), end);
        }

        value = value.Trim().Trim('"', '\'');
        return value.Length == 0 ? null : value;
    }

    private static bool ParseDirectBool(
        string[] lines,
        string key,
        int start,
        int end,
        bool allowSequencePrefix = false)
    {
        var value = ParseDirectScalar(lines, key, start, end, allowSequencePrefix);
        return value is not null && value.Equals("true", StringComparison.OrdinalIgnoreCase);
    }

    private static int FindTopLevelKey(string[] lines, string key, int start = 0, int? end = null)
    {
        end ??= lines.Length;
        for (var i = start; i < end.Value; i++)
        {
            if (IsBlankOrComment(lines[i]) || GetIndentation(lines[i]) != 0)
            {
                continue;
            }

            if (TryGetLineValue(lines[i], key, allowSequencePrefix: false) is not null)
            {
                return i;
            }
        }

        return -1;
    }

    private static int FindDirectChildKey(
        string[] lines,
        string key,
        int parentIndent,
        int start,
        int end,
        bool allowSequencePrefix = false)
    {
        var childIndent = FindFirstChildIndent(lines, start, parentIndent, end);
        if (childIndent is null)
        {
            return -1;
        }

        for (var i = start + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= parentIndent)
            {
                break;
            }

            if (indent != childIndent.Value)
            {
                continue;
            }

            if (TryGetLineValue(lines[i], key, allowSequencePrefix) is not null)
            {
                return i;
            }
        }

        return -1;
    }

    private static int FindBlockEnd(string[] lines, int start, int baseIndent, int end)
    {
        for (var i = start + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            if (GetIndentation(lines[i]) <= baseIndent)
            {
                return i;
            }
        }

        return end;
    }

    private static int? FindFirstChildIndent(string[] lines, int headerIndex, int headerIndent, int end)
    {
        for (var i = headerIndex + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= headerIndent)
            {
                return null;
            }

            return indent;
        }

        return null;
    }

    private static string ParseKeyName(string line)
    {
        var trimmed = line.TrimStart();
        if (trimmed.StartsWith("-", StringComparison.Ordinal))
        {
            trimmed = trimmed[1..].TrimStart();
        }

        var colonIndex = trimmed.IndexOf(':', StringComparison.Ordinal);
        return colonIndex < 0 ? string.Empty : trimmed[..colonIndex].Trim().Trim('"', '\'');
    }

    private static string? TryGetLineValue(string line, string key, bool allowSequencePrefix)
    {
        var trimmed = line.TrimStart();
        if (allowSequencePrefix && trimmed.StartsWith("-", StringComparison.Ordinal))
        {
            trimmed = trimmed[1..].TrimStart();
        }

        if (!trimmed.StartsWith(key + ":", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return trimmed[(key.Length + 1)..].Trim();
    }

    /// <summary>
    /// Parses an inline YAML flow mapping: { key: value, key2: value2 }
    /// Returns null if the line does not contain a flow mapping.
    /// </summary>
    private static Dictionary<string, string>? TryParseFlowMapping(string line, string key)
    {
        var value = TryGetLineValue(line, key, allowSequencePrefix: false);
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        if (!value.StartsWith('{') || !value.EndsWith('}')) return null;

        // Empty mapping: {}
        var inner = value[1..^1].Trim();
        if (inner.Length == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var entries = SplitFlowMappingEntries(inner);
        foreach (var entry in entries)
        {
            var colonIdx = entry.IndexOf(':');
            if (colonIdx < 0) continue;
            var entryKey = entry[..colonIdx].Trim();
            var entryValue = entry[(colonIdx + 1)..].Trim().Trim('"', '\'');
            if (entryKey.Length > 0)
                result[entryKey] = entryValue;
        }

        return result;
    }

    /// <summary>
    /// Splits flow mapping entries by comma, respecting simple quoting.
    /// </summary>
    private static string[] SplitFlowMappingEntries(string inner)
    {
        var entries = new List<string>();
        var depth = 0;
        var inQuote = false;
        var start = 0;
        for (var i = 0; i < inner.Length; i++)
        {
            var c = inner[i];
            if (c == '"' && !inQuote) { inQuote = true; continue; }
            if (c == '"' && inQuote) { inQuote = false; continue; }
            if (inQuote) continue;
            if (c is '{' or '[') depth++;
            else if (c is '}' or ']') depth--;
            else if (c == ',' && depth == 0)
            {
                entries.Add(inner[start..i]);
                start = i + 1;
            }
        }
        entries.Add(inner[start..]);
        return entries.ToArray();
    }

    private static IReadOnlyList<string> ParseInlineListOrScalar(string value)
    {
        value = value.Trim();
        if (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal))
        {
            return value.Trim('[', ']')
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(item => item.Trim('"', '\''))
                .Where(item => item.Length > 0)
                .ToArray();
        }

        return [value.Trim('"', '\'')];
    }

    private static string ParseMultilineValue(string[] lines, int headerIndex, int headerIndent, int end)
    {
        var values = new List<string>();
        for (var i = headerIndex + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                values.Add(string.Empty);
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= headerIndent)
            {
                break;
            }

            values.Add(lines[i].TrimStart());
        }

        return string.Join('\n', values).Trim();
    }

    private static string ParseIndentedList(string[] lines, int headerIndex, int headerIndent, int end)
    {
        var values = new List<string>();
        for (var i = headerIndex + 1; i < end; i++)
        {
            if (IsBlankOrComment(lines[i]))
            {
                continue;
            }

            var indent = GetIndentation(lines[i]);
            if (indent <= headerIndent)
            {
                break;
            }

            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith("-", StringComparison.Ordinal))
            {
                var item = trimmed[1..].Trim().Trim('"', '\'');
                if (item.Length > 0)
                {
                    values.Add(item);
                }
            }
        }

        return string.Join('\n', values);
    }

    private static string[] SplitLines(string content) =>
        content.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');

    private static bool IsBlankOrComment(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.Length == 0 || trimmed[0] == '#';
    }

    private static int GetIndentation(string line)
    {
        var count = 0;
        foreach (var c in line)
        {
            if (c == ' ')
            {
                count++;
            }
            else if (c == '\t')
            {
                count += 4;
            }
            else
            {
                break;
            }
        }

        return count;
    }
}

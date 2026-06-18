using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.Kubernetes;

/// <summary>
/// Conservative, line-oriented parser for Kubernetes workload manifests.
/// Tolerates Helm template placeholders and malformed input; returns warnings instead of throwing.
/// </summary>
internal static partial class KubernetesWorkloadParser
{
    public static KubernetesWorkloadDocument Parse(string relativePath, string content)
    {
        var warnings = new List<string>();
        var workloads = new List<KubernetesWorkload>();
        var lines = content.Replace("\r\n", "\n").Split('\n');

        var documents = SplitDocuments(lines);
        foreach (var docRange in documents)
        {
            var kind = ReadKind(lines, docRange);
            if (!IsWorkloadKind(kind))
            {
                continue;
            }

            string? name;
            try { name = ReadMetadataName(lines, docRange); }
            catch (Exception ex) { warnings.Add($"ReadMetadataName: {ex.Message}"); name = null; }

            string? ns;
            try { ns = ReadMetadataNamespace(lines, docRange); }
            catch (Exception ex) { warnings.Add($"ReadMetadataNamespace: {ex.Message}"); ns = null; }

            KubernetesSecurityContext podSecurityContext;
            try { podSecurityContext = ReadPodSecurityContext(lines, docRange, kind); }
            catch (Exception ex) { warnings.Add($"ReadPodSecurityContext: {ex.Message}"); podSecurityContext = EmptySecurityContext(); }

            IReadOnlyList<LineRange> containerRanges;
            try { containerRanges = FindContainerRanges(lines, docRange, kind); }
            catch (Exception ex) { warnings.Add($"FindContainerRanges: {ex.Message}"); containerRanges = []; }

            var containers = new List<KubernetesContainer>();

            foreach (var containerRange in containerRanges)
            {
                var containerSecurityContext = ReadContainerSecurityContext(lines, containerRange);
                var resources = ReadResourceRequirements(lines, containerRange);
                var containerName = ReadContainerName(lines, containerRange);
                containers.Add(new KubernetesContainer(
                    containerName,
                    containerSecurityContext,
                    resources,
                    containerRange.Start + 1));
            }

            var workload = new KubernetesWorkload(
                kind,
                name,
                ns,
                containers,
                podSecurityContext,
                docRange.Start + 1);

            workloads.Add(workload);
        }

        return new KubernetesWorkloadDocument(relativePath, workloads, warnings);
    }

    // ── Document splitting ──────────────────────────────────────────

    private static IReadOnlyList<LineRange> SplitDocuments(string[] lines)
    {
        var ranges = new List<LineRange>();
        var start = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            if (DocumentSeparatorRegex().IsMatch(lines[i]))
            {
                ranges.Add(new LineRange(start, i));
                start = i + 1;
            }
        }
        ranges.Add(new LineRange(start, lines.Length));
        return ranges;
    }

    // ── Kind detection ──────────────────────────────────────────────

    private static string ReadKind(string[] lines, LineRange docRange)
    {
        for (var i = docRange.Start; i < docRange.EndExclusive; i++)
        {
            var match = KindRegex.Match(lines[i]);
            if (match.Success)
            {
                return match.Groups["kind"].Value;
            }
        }
        return string.Empty;
    }

    private static readonly Regex KindRegex = new(
        @"^\s*kind\s*:\s*(?<kind>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static bool IsWorkloadKind(string kind) => kind switch
    {
        "Deployment" or "StatefulSet" or "DaemonSet" or "Job" or "CronJob" or "Pod" => true,
        _ => false
    };

    // ── Name / Namespace ─────────────────────────────────────────────

    private static string? ReadMetadataName(string[] lines, LineRange docRange)
    {
        var inMetadata = false;
        var metadataIndent = -1;
        foreach (var range in EnumerateLines(lines, docRange))
        {
            var line = lines[range.Index];
            var trimmed = line.TrimStart();
            if (trimmed == "metadata:" || trimmed.StartsWith("metadata:", StringComparison.Ordinal))
            {
                inMetadata = true;
                metadataIndent = CountIndent(line);
                continue;
            }
            if (inMetadata)
            {
                var indent = CountIndent(line);
                if (indent <= metadataIndent)
                {
                    break;
                }
                var match = NameLineRegex().Match(trimmed);
                if (match.Success)
                {
                    return match.Groups["name"].Value.Trim('"', '\'');
                }
            }
        }
        return null;
    }

    private static string? ReadMetadataNamespace(string[] lines, LineRange docRange)
    {
        var inMetadata = false;
        var metadataIndent = -1;
        foreach (var range in EnumerateLines(lines, docRange))
        {
            var line = lines[range.Index];
            var trimmed = line.TrimStart();
            if (trimmed == "metadata:" || trimmed.StartsWith("metadata:", StringComparison.Ordinal))
            {
                inMetadata = true;
                metadataIndent = CountIndent(line);
                continue;
            }
            if (inMetadata)
            {
                var indent = CountIndent(line);
                if (indent <= metadataIndent)
                {
                    break;
                }
                var match = NamespaceLineRegex().Match(trimmed);
                if (match.Success)
                {
                    return match.Groups["namespace"].Value.Trim('"', '\'');
                }
            }
        }
        return null;
    }

    // ── Container path resolution ────────────────────────────────────

    /// <summary>
    /// Returns the sequence of path segments needed to reach containers for a given workload kind.
    /// Only the last element (null-terminated) is the containers list key.
    /// </summary>
    private static IReadOnlyList<string> ContainerPathForKind(string kind) => kind switch
    {
        "CronJob" => ["spec", "jobTemplate", "spec", "template", "spec", "containers"],
        "Pod" => ["spec", "containers"],
        _ => ["spec", "template", "spec", "containers"]
    };

    private static IReadOnlyList<LineRange> FindContainerRanges(string[] lines, LineRange docRange, string kind)
    {
        var path = ContainerPathForKind(kind);
        var containersKeyLine = FindContainersKey(lines, docRange, path);
        if (containersKeyLine < 0)
        {
            return [];
        }

        var blockIndent = CountIndent(lines[containersKeyLine]);
        var blockEnd = FindBlockEnd(lines, containersKeyLine + 1, blockIndent, docRange.EndExclusive);
        var itemIndent = FindFirstListItemIndent(lines, containersKeyLine + 1, blockEnd, blockIndent);

        if (itemIndent is null)
        {
            return [];
        }

        var ranges = new List<LineRange>();
        for (var cursor = containersKeyLine + 1; cursor < blockEnd; cursor++)
        {
            if (!IsListItem(lines[cursor], itemIndent.Value))
            {
                continue;
            }

            var itemEnd = FindItemEnd(lines, cursor + 1, blockEnd, itemIndent.Value);
            ranges.Add(new LineRange(cursor, itemEnd));
            cursor = itemEnd - 1;
        }

        return ranges;
    }

    private static int FindContainersKey(string[] lines, LineRange docRange, IReadOnlyList<string> path)
    {
        // Walk the path segments in order through YAML indentation levels.
        var expectedIndent = 0;
        var currentIndex = docRange.Start;

        for (var segmentIdx = 0; segmentIdx < path.Count; segmentIdx++)
        {
            var segment = path[segmentIdx];
            var found = false;

            for (var i = currentIndex; i < docRange.EndExclusive; i++)
            {
                var line = lines[i];
                var trimmed = line.TrimStart();
                var indent = CountIndent(line);

                if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
                {
                    continue;
                }

                // If we encounter a line with less indent than expected,
                // the parent block has ended — path not found.
                if (indent < expectedIndent && !IsDocumentSeparator(line))
                {
                    return -1;
                }

                // For the final segment ("containers") we look for the exact key.
                // For intermediate segments, we look for the key followed by a value or colon.
                var keyMatch = trimmed == $"{segment}:" || trimmed.StartsWith($"{segment}:", StringComparison.Ordinal);
                if (!keyMatch)
                {
                    continue;
                }

                if (indent != expectedIndent && segmentIdx > 0)
                {
                    continue;
                }

                found = true;
                currentIndex = i + 1;
                expectedIndent = indent + 2; // next segment should be nested deeper.
                break;
            }

            if (!found)
            {
                return -1;
            }
        }

        // We should have found the last segment (containers:). currentIndex points after it.
        return currentIndex - 1;
    }

    // ── Container name ───────────────────────────────────────────────

    private static string ReadContainerName(string[] lines, LineRange containerRange)
    {
        foreach (var range in EnumerateLines(lines, containerRange))
        {
            var trimmed = lines[range.Index].TrimStart();
            var match = ContainerNameLineRegex().Match(trimmed);
            if (match.Success)
            {
                return match.Groups["name"].Value.Trim('"', '\'');
            }
        }
        return "<unnamed>";
    }

    // ── Security context ─────────────────────────────────────────────

    private static KubernetesSecurityContext ReadPodSecurityContext(string[] lines, LineRange docRange, string kind)
    {
        var path = ContainerPathForKind(kind);
        // Pod security context is just before "containers" in the path.
        // For "spec.template.spec.containers", the pod sc is at "spec.template.spec.securityContext"
        // For "spec.containers", pod sc is at "spec.securityContext"
        // For CronJob: "spec.jobTemplate.spec.template.spec.securityContext"

        var podScPath = GetPodSecurityContextPath(kind);
        var scLine = FindKeyAtPath(lines, docRange, podScPath);
        if (scLine < 0)
        {
            return EmptySecurityContext();
        }

        var scBlockIndent = CountIndent(lines[scLine]);
        var scBlockEnd = FindBlockEnd(lines, scLine + 1, scBlockIndent, docRange.EndExclusive);
        var scRange = new LineRange(scLine + 1, scBlockEnd);
        return ParseSecurityContextBlock(lines, scRange, scLine + 1);
    }

    private static IReadOnlyList<string> GetPodSecurityContextPath(string kind) => kind switch
    {
        "CronJob" => ["spec", "jobTemplate", "spec", "template", "spec", "securityContext"],
        "Pod" => ["spec", "securityContext"],
        _ => ["spec", "template", "spec", "securityContext"]
    };

    private static KubernetesSecurityContext ReadContainerSecurityContext(string[] lines, LineRange containerRange)
    {
        var scLine = FindKey(lines, containerRange, "securityContext");
        if (scLine < 0)
        {
            return EmptySecurityContext();
        }

        var scBlockIndent = CountIndent(lines[scLine]);
        var scBlockEnd = FindBlockEnd(lines, scLine + 1, scBlockIndent, containerRange.EndExclusive);
        var scRange = new LineRange(scLine + 1, scBlockEnd);
        return ParseSecurityContextBlock(lines, scRange, scLine + 1);
    }

    private static KubernetesSecurityContext ParseSecurityContextBlock(string[] lines, LineRange blockRange, int startLine)
    {
        string? seccompProfileType = null;
        var capabilityAdds = new List<string>();
        var capabilityDrops = new List<string>();
        int? scStartLine = startLine;

        for (var i = blockRange.Start; i < blockRange.EndExclusive; i++)
        {
            var line = lines[i];
            var trimmed = line.TrimStart();

            if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
            {
                continue;
            }

            // seccompProfile detection
            if (trimmed == "seccompProfile:" || trimmed.StartsWith("seccompProfile:", StringComparison.Ordinal))
            {
                seccompProfileType = ReadSeccompType(lines, i, blockRange.EndExclusive);
                continue;
            }

            // capabilities block
            if (trimmed == "capabilities:" || trimmed.StartsWith("capabilities:", StringComparison.Ordinal))
            {
                var capBlockIndent = CountIndent(line);
                var capBlockEnd = FindBlockEnd(lines, i + 1, capBlockIndent, blockRange.EndExclusive);
                (capabilityAdds, capabilityDrops) = ReadCapabilities(lines, i + 1, capBlockEnd, capBlockIndent);
                continue;
            }
        }

        return new KubernetesSecurityContext(
            seccompProfileType,
            capabilityAdds,
            capabilityDrops,
            scStartLine);
    }

    private static string? ReadSeccompType(string[] lines, int seccompLineIndex, int blockEnd)
    {
        var blockIndent = CountIndent(lines[seccompLineIndex]);
        for (var i = seccompLineIndex + 1; i < blockEnd; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
            {
                continue;
            }

            var indent = CountIndent(line);
            if (indent <= blockIndent)
            {
                break;
            }

            var match = SeccompTypeLineRegex().Match(line.TrimStart());
            if (match.Success)
            {
                var type = match.Groups["type"].Value.Trim('"', '\'');
                return type;
            }
        }
        return null;
    }

    private static (List<string> Adds, List<string> Drops) ReadCapabilities(
        string[] lines, int start, int blockEnd, int blockIndent)
    {
        var adds = new List<string>();
        var drops = new List<string>();

        for (var i = start; i < blockEnd; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
            {
                continue;
            }

            var indent = CountIndent(line);
            if (indent <= blockIndent)
            {
                break;
            }

            var trimmed = line.TrimStart();

            // add: list
            if (trimmed == "add:" || trimmed.StartsWith("add:", StringComparison.Ordinal))
            {
                var items = ReadCapabilityListItems(lines, i, blockEnd, indent);
                adds.AddRange(items);
                continue;
            }

            // drop: list
            if (trimmed == "drop:" || trimmed.StartsWith("drop:", StringComparison.Ordinal))
            {
                var items = ReadCapabilityListItems(lines, i, blockEnd, indent);
                drops.AddRange(items);
                continue;
            }
        }

        // Normalize: trim quotes, uppercase
        return (
            adds.Select(static c => c.Trim('"', '\'').ToUpperInvariant()).Where(static c => c.Length > 0).ToList(),
            drops.Select(static c => c.Trim('"', '\'').ToUpperInvariant()).Where(static c => c.Length > 0).ToList()
        );
    }

    private static List<string> ReadCapabilityListItems(string[] lines, int keyLine, int blockEnd, int keyIndent)
    {
        var items = new List<string>();
        // Check for inline array: add: ["SYS_ADMIN"]
        var inlineMatch = InlineArrayRegex().Match(lines[keyLine].TrimStart());
        if (inlineMatch.Success)
        {
            var values = inlineMatch.Groups["values"].Value;
            foreach (Match m in QuotedValueRegex().Matches(values))
            {
                items.Add(m.Groups["val"].Value);
            }
            return items;
        }

        // Block-style list
        for (var i = keyLine + 1; i < blockEnd; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
            {
                continue;
            }

            var indent = CountIndent(line);
            if (indent < keyIndent)
            {
                break;
            }
            // List items at same indent as the key (e.g. "- SYS_ADMIN" under "add:")
            // are part of the key's value and should be included.
            if (indent == keyIndent && !line.TrimStart().StartsWith("- ", StringComparison.Ordinal) && line.TrimStart() != "-")
            {
                break;
            }

            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed == "-")
            {
                var val = trimmed["- ".Length..].Trim();
                if (val.Length > 0)
                {
                    items.Add(val);
                }
                else if (i + 1 < blockEnd)
                {
                    // Value on next line (rare)
                    var nextTrimmed = lines[i + 1].TrimStart();
                    if (!nextTrimmed.StartsWith("- ", StringComparison.Ordinal) && nextTrimmed != "-")
                    {
                        items.Add(nextTrimmed);
                    }
                }
            }
        }

        return items;
    }

    // ── Resources ────────────────────────────────────────────────────

    private static KubernetesResourceRequirements ReadResourceRequirements(string[] lines, LineRange containerRange)
    {
        var resourcesLine = FindKey(lines, containerRange, "resources");
        if (resourcesLine < 0)
        {
            return new KubernetesResourceRequirements(false, false, null);
        }

        var blockIndent = CountIndent(lines[resourcesLine]);
        var blockEnd = FindBlockEnd(lines, resourcesLine + 1, blockIndent, containerRange.EndExclusive);

        // Find "limits:" within resources block
        var limitsLine = FindKeyInRange(lines, resourcesLine + 1, blockEnd, "limits");
        if (limitsLine < 0)
        {
            return new KubernetesResourceRequirements(false, false, resourcesLine + 1);
        }

        var limitsIndent = CountIndent(lines[limitsLine]);
        var limitsEnd = FindBlockEnd(lines, limitsLine + 1, limitsIndent, blockEnd);

        var hasCpu = false;
        var hasMemory = false;

        for (var i = limitsLine + 1; i < limitsEnd; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (string.IsNullOrWhiteSpace(lines[i]) || IsCommentLine(lines[i]))
            {
                continue;
            }

            var indent = CountIndent(lines[i]);
            if (indent <= limitsIndent)
            {
                break;
            }

            if (CpuLimitRegex().IsMatch(trimmed))
            {
                hasCpu = true;
            }
            else if (MemoryLimitRegex().IsMatch(trimmed))
            {
                hasMemory = true;
            }
        }

        return new KubernetesResourceRequirements(hasCpu, hasMemory, limitsLine + 1);
    }

    // ── Path walking helpers ─────────────────────────────────────────

    /// <summary>
    /// Find a key at a specific YAML path within a document range.
    /// Returns the line index of the last path segment, or -1 if not found.
    /// </summary>
    private static int FindKeyAtPath(string[] lines, LineRange docRange, IReadOnlyList<string> path)
    {
        var expectedIndent = 0;
        var currentIndex = docRange.Start;

        for (var segmentIdx = 0; segmentIdx < path.Count; segmentIdx++)
        {
            var segment = path[segmentIdx];
            var found = false;
            for (var i = currentIndex; i < docRange.EndExclusive; i++)
            {
                var line = lines[i];
                var indent = CountIndent(line);

                if (string.IsNullOrWhiteSpace(line) || IsCommentLine(line))
                {
                    continue;
                }

                if (indent < expectedIndent)
                {
                    return -1;
                }

                var trimmed = line.TrimStart();
                if (trimmed == $"{segment}:" || trimmed.StartsWith($"{segment}:", StringComparison.Ordinal))
                {
                    if (indent == expectedIndent)
                    {
                        found = true;
                        currentIndex = i + 1;
                        expectedIndent = indent + 2;
                        break;
                    }
                }
            }

            if (!found)
            {
                return -1;
            }
        }

        return currentIndex - 1;
    }

    private static int FindKey(string[] lines, LineRange range, string key)
    {
        return FindKeyInRange(lines, range.Start, range.EndExclusive, key);
    }

    private static int FindKeyInRange(string[] lines, int start, int end, string key)
    {
        for (var i = start; i < end; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed == $"{key}:" || trimmed.StartsWith($"{key}:", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    // ── YAML structure helpers ───────────────────────────────────────

    private static int FindBlockEnd(string[] lines, int start, int blockIndent, int maxEnd)
    {
        for (var i = start; i < maxEnd; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i]))
            {
                continue;
            }

            var indent = CountIndent(lines[i]);
            if (indent < blockIndent)
            {
                return i;
            }
            // List items (starting with "- ") at the same indent belong to the
            // parent key's value block (e.g. "containers:" followed by "- name:").
            if (indent == blockIndent && !lines[i].TrimStart().StartsWith("- ", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return maxEnd;
    }

    private static int? FindFirstListItemIndent(string[] lines, int start, int blockEnd, int blockIndent)
    {
        for (var i = start; i < blockEnd; i++)
        {
            if (CountIndent(lines[i]) >= blockIndent && lines[i].TrimStart().StartsWith("- ", StringComparison.Ordinal))
            {
                return CountIndent(lines[i]);
            }
        }

        return null;
    }

    private static int FindItemEnd(string[] lines, int start, int blockEnd, int itemIndent)
    {
        for (var i = start; i < blockEnd; i++)
        {
            if (IsListItem(lines[i], itemIndent))
            {
                return i;
            }
        }

        return blockEnd;
    }

    private static bool IsListItem(string line, int indent) =>
        CountIndent(line) == indent && line.TrimStart().StartsWith("- ", StringComparison.Ordinal);

    private static int CountIndent(string line)
    {
        var count = 0;
        while (count < line.Length && line[count] == ' ')
        {
            count++;
        }
        return count;
    }

    private static bool IsCommentLine(string line) =>
        line.TrimStart().StartsWith('#');

    private static bool IsDocumentSeparator(string line) =>
        line.TrimStart() == "---";

    // ── Enumerate lines helper ───────────────────────────────────────

    private static IEnumerable<(int Index, string Line)> EnumerateLines(string[] lines, LineRange range)
    {
        for (var i = range.Start; i < range.EndExclusive; i++)
        {
            yield return (i, lines[i]);
        }
    }

    private static KubernetesSecurityContext EmptySecurityContext() =>
        new(null, [], [], null);

    // ── Regex helpers ────────────────────────────────────────────────

    [GeneratedRegex(@"^\s*---\s*(?:#.*)?$")]
    private static partial Regex DocumentSeparatorRegex();

    [GeneratedRegex(@"^\s*kind\s*:\s*(?<kind>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex KindLineRegex();

    [GeneratedRegex(@"^\s*-\s*name\s*:\s*(?<name>[^#\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex ContainerNameLineRegex();

    [GeneratedRegex(@"^\s*name\s*:\s*(?<name>[^#\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex NameLineRegex();

    [GeneratedRegex(@"^\s*namespace\s*:\s*(?<namespace>[^#\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex NamespaceLineRegex();

    [GeneratedRegex(@"^\s*type\s*:\s*(?<type>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SeccompTypeLineRegex();

    [GeneratedRegex(@"^\s*cpu\s*:\s*\S", RegexOptions.IgnoreCase)]
    private static partial Regex CpuLimitRegex();

    [GeneratedRegex(@"^\s*memory\s*:\s*\S", RegexOptions.IgnoreCase)]
    private static partial Regex MemoryLimitRegex();

    [GeneratedRegex(@"\[(?<values>[^\]]+)\]")]
    private static partial Regex InlineArrayRegex();

    [GeneratedRegex(@"""(?<val>[^""]*)""|'(?<val>[^']*)'|(?<val>\S+)")]
    private static partial Regex QuotedValueRegex();

    private sealed record LineRange(int Start, int EndExclusive);
}

using System.Text.RegularExpressions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.GitHubActions;

public sealed partial class GitHubActionsBasicAnalyzer
{
    private static void CheckShellInjection(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (RunBlockPattern().IsMatch(line))
            {
                var isMultiLine = line.Contains('|') || line.Contains('>');
                var baseIndentation = GetIndentation(line);

                if (!isMultiLine)
                {
                    if (HasInjectionPattern(line))
                    {
                        AddFinding(findings, "TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", Severity.High, "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead.", relativePath, "Potential shell injection found in run block.", i + 1, Confidence.Medium);
                    }
                }
                else
                {
                    for (int j = i + 1; j < lines.Length; j++)
                    {
                        var subLine = lines[j];
                        if (string.IsNullOrWhiteSpace(subLine))
                        {
                            continue;
                        }

                        var subIndentation = GetIndentation(subLine);
                        if (subIndentation <= baseIndentation)
                        {
                            break;
                        }

                        if (HasInjectionPattern(subLine))
                        {
                            AddFinding(findings, "TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", Severity.High, "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead.", relativePath, "Potential shell injection found in multiline run block.", j + 1, Confidence.Medium);
                            break;
                        }
                    }
                }
            }
        }
    }

    private static int GetIndentation(string line)
    {
        int count = 0;
        foreach (var c in line)
        {
            if (c == ' ') count++;
            else if (c == '\t') count += 4;
            else break;
        }
        return count;
    }

    private static bool HasInjectionPattern(string line)
    {
        return InjectionPattern().IsMatch(line);
    }

    private static void CheckReleaseWorkflowDependency(string content, string relativePath, List<Finding> findings)
    {
        if (!ReleasePublishPattern().IsMatch(content))
        {
            return;
        }

        if (TestDependencyPattern().IsMatch(content))
        {
            return;
        }

        var match = ReleasePublishPattern().Match(content);
        AddFinding(
            findings,
            "TRUST-GHA009",
            "Release workflow may publish without test dependency",
            Severity.High,
            "Make release or publish jobs depend on a test or CI job before publishing artifacts or packages.",
            relativePath,
            "Release or package publishing command was found without a visible test dependency.",
            GetLineNumber(content, match.Index),
            Confidence.Medium);
    }

    private static void CheckArtifactUploadPaths(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (var index = 0; index < lines.Length; index++)
        {
            if (!UploadArtifactPattern().IsMatch(lines[index]))
            {
                continue;
            }

            var checkLimit = Math.Min(index + 12, lines.Length);
            for (var cursor = index + 1; cursor < checkLimit; cursor++)
            {
                var pathMatch = BroadArtifactPathPattern().Match(lines[cursor]);
                if (!pathMatch.Success)
                {
                    continue;
                }

                AddFinding(
                    findings,
                    "TRUST-GHA010",
                    "Workflow uploads overly broad artifact path",
                    Severity.Medium,
                    "Upload only specific build outputs and avoid broad artifact paths that may include source, secrets, or temporary files.",
                    relativePath,
                    $"Artifact upload path is overly broad: {pathMatch.Groups["path"].Value.Trim()}",
                    cursor + 1,
                    Confidence.Medium);
                break;
            }
        }
    }

    private static void CheckTokenScope(string content, string relativePath, List<Finding> findings)
    {
        var workflowHeader = GetTopLevelWorkflowHeader(content);
        var permsMatch = PermissionsPattern().Match(workflowHeader);
        if (!permsMatch.Success)
        {
            return;
        }

        if (WriteAllPattern().IsMatch(workflowHeader) ||
            WorkflowWritePermPattern().IsMatch(workflowHeader))
        {
            return;
        }

        if (!PermissionsGrantWriteScope(workflowHeader, permsMatch.Index))
        {
            return;
        }

        AddFinding(
            findings,
            "TRUST-GHA011",
            "Workflow does not restrict GITHUB_TOKEN scope",
            Severity.Medium,
            "Prefer read-only workflow permissions and grant write scopes only on the specific job that needs them.",
            relativePath,
            "Workflow-level permissions grant write access to GITHUB_TOKEN.",
            GetLineNumber(content, permsMatch.Index),
            Confidence.Medium);
    }

    private static bool PermissionsGrantWriteScope(string content, int permissionsIndex)
    {
        var lines = SplitLines(content);
        var currentOffset = 0;
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index];
            var nextOffset = currentOffset + line.Length + 1;
            if (permissionsIndex >= currentOffset && permissionsIndex < nextOffset)
            {
                var trimmed = line.Trim();
                if (trimmed.Equals("permissions: write-all", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (trimmed.Equals("permissions: read-all", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Equals("permissions: {}", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                var baseIndent = GetIndentation(line);
                for (var cursor = index + 1; cursor < lines.Length; cursor++)
                {
                    var child = lines[cursor];
                    if (string.IsNullOrWhiteSpace(child))
                    {
                        continue;
                    }

                    if (GetIndentation(child) <= baseIndent)
                    {
                        break;
                    }

                    var writeMatch = PermissionWriteValuePattern().Match(child);
                    if (writeMatch.Success &&
                        IsRepositoryMutatingPermissionScope(writeMatch.Groups["scope"].Value))
                    {
                        return true;
                    }
                }

                return false;
            }

            currentOffset = nextOffset;
        }

        return false;
    }

    private static bool IsRepositoryMutatingPermissionScope(string scope) =>
        scope.Equals("contents", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("packages", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("actions", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("pull-requests", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("issues", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("checks", StringComparison.OrdinalIgnoreCase) ||
        scope.Equals("deployments", StringComparison.OrdinalIgnoreCase);

    private static void CheckHardcodedSecretsInEnv(string content, string relativePath, List<Finding> findings)
    {
        var match = HardcodedSecretEnvPattern().Match(content);
        if (match.Success)
        {
            var value = match.Groups["value"].Value.Trim('"', '\'');
            if (IsSafeEnvReference(value))
            {
                return;
            }

            var redactedValue = value.Length > 4
                ? value[..4] + "[redacted]"
                : "[redacted]";
            AddFinding(
                findings,
                "TRUST-GHA013",
                "Workflow may contain hardcoded secret in step env",
                Severity.High,
                "Use GitHub Secrets instead of inline values for credentials and tokens.",
                relativePath,
                $"A step sets an environment variable '{match.Groups["key"].Value}' with a secret-like value: {redactedValue}",
                confidence: Confidence.Medium);
        }
    }

    private static bool IsSafeEnvReference(string value) =>
        value.Contains("${{", StringComparison.Ordinal) ||
        value.StartsWith("$", StringComparison.Ordinal) ||
        value.Contains("example", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("placeholder", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("changeme", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("replace-me", StringComparison.OrdinalIgnoreCase);

    private static bool CheckPrTargetSecretsExposure(string content, string relativePath, List<Finding> findings)
    {
        if (!PullRequestTargetPattern().IsMatch(content))
        {
            return false;
        }

        if (ChecksOutPullRequestHead(content))
        {
            AddFinding(findings, "TRUST-GHA015", "pull_request_target exposes secrets",
                Severity.High, "Avoid checking out untrusted PR code or using secrets in pull_request_target workflows.",
                relativePath, "pull_request_target workflow checks out pull request head code.");
            return true;
        }

        return false;
    }

    private static bool ChecksOutPullRequestHead(string content)
    {
        var lines = SplitLines(content);
        for (var index = 0; index < lines.Length; index++)
        {
            if (!UsesCheckoutPattern().IsMatch(lines[index]))
            {
                continue;
            }

            var baseIndentation = GetCheckoutStepBaseIndentation(lines, index);
            for (var cursor = index + 1; cursor < lines.Length; cursor++)
            {
                var line = lines[cursor];
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                if (GetIndentation(line) <= baseIndentation)
                {
                    break;
                }

                if (ReferencesPullRequestHead(line))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool ReferencesPullRequestHead(string line) =>
        line.Contains("github.event.pull_request.head", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("github.head_ref", StringComparison.OrdinalIgnoreCase);

    private static void CheckWorkflowWritePermissions(string content, string relativePath, List<Finding> findings)
    {
        var permSection = GetTopLevelWorkflowHeader(content);

        if (WorkflowWritePermPattern().IsMatch(permSection))
        {
            AddFinding(findings, "TRUST-GHA016", "Broad workflow write permissions",
                Severity.Medium, "Reduce permissions to least privilege per job.",
                relativePath, "Top-level permissions grant repository-mutating write scope.",
                confidence: Confidence.Medium);
        }
    }

    private static void CheckBroadCachePaths(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in CacheBroadPathPattern().Matches(content))
        {
            var path = match.Groups["path"].Value.Trim();
            var normalized = path.Trim('"', '\'', '/', '.').Trim();
            if (string.IsNullOrEmpty(normalized) || normalized is "~" || normalized.Contains("github.workspace"))
            {
                AddFinding(findings, "TRUST-GHA017", "Broad cache path",
                    Severity.Low, "Narrow cache paths to specific package directories.",
                    relativePath, $"Cache path '{path}' is overly broad.",
                    confidence: Confidence.Medium);
                break;
            }
        }
    }

    private static string GetTopLevelWorkflowHeader(string content)
    {
        var normalized = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var lines = normalized.Split('\n');
        var offset = 0;

        foreach (var line in lines)
        {
            if (GetIndentation(line) == 0 && line.TrimStart().StartsWith("jobs:", StringComparison.OrdinalIgnoreCase))
            {
                return normalized[..offset];
            }

            offset += line.Length + 1;
        }

        return normalized;
    }

    private static void CheckJobContainerLatest(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in JobContainerImagePattern().Matches(content))
        {
            var image = match.Groups["image"].Value.Trim();
            if (image.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
                continue;

            var tag = GetContainerImageTag(image);
            if (tag is null || tag.Equals("latest", StringComparison.OrdinalIgnoreCase))
            {
                AddFinding(findings, "TRUST-GHA018", "Unpinned container image",
                    Severity.Medium, "Pin container images to specific versions or digests.",
                    relativePath, $"Container image '{image}' uses :latest or no tag.",
                    GetLineNumber(content, match.Index));
            }
        }
    }

    private static void CheckMatrixInjection(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (int i = 0; i < lines.Length; i++)
        {
            if (!RunBlockPattern().IsMatch(lines[i]))
            {
                continue;
            }

            var isMultiLine = lines[i].Contains('|') || lines[i].Contains('>');
            var findingLine = MatrixInjectionPattern().IsMatch(lines[i])
                ? i
                : isMultiLine
                    ? FindIndentedMatch(lines, i, MatrixInjectionPattern())
                    : -1;
            if (findingLine >= 0)
            {
                AddFinding(
                    findings,
                    "TRUST-GHA014",
                    "Workflow may interpolate matrix values in shell",
                    Severity.High,
                    "Avoid direct inline shell interpolation of matrix values. Pass matrix values as environment variables instead.",
                    relativePath,
                    "Potential matrix injection found in run block.",
                    findingLine + 1,
                    Confidence.Medium);
                break;
            }
        }
    }

    private static int FindIndentedMatch(string[] lines, int headerIndex, Regex pattern)
    {
        var baseIndentation = GetIndentation(lines[headerIndex]);
        for (var index = headerIndex + 1; index < lines.Length; index++)
        {
            if (string.IsNullOrWhiteSpace(lines[index]))
            {
                continue;
            }

            if (GetIndentation(lines[index]) <= baseIndentation)
            {
                break;
            }

            if (pattern.IsMatch(lines[index]))
            {
                return index;
            }
        }

        return -1;
    }

    private static string? GetContainerImageTag(string image)
    {
        var lastSlash = image.LastIndexOf('/');
        var lastColon = image.LastIndexOf(':');
        return lastColon > lastSlash ? image[(lastColon + 1)..] : null;
    }

    private static string[] SplitLines(string content) => content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');

    private static bool IsPinnedToSha(string value) => ShaPattern().IsMatch(value);

    private static void AddFinding(List<Finding> findings, string ruleId, string title, Severity severity, string recommendation, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.CiCd,
            severity,
            confidence,
            title,
            [new Evidence("workflow", evidence, filePath, lineNumber)],
            new Recommendation(recommendation)));
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var index = 0; index < matchIndex && index < content.Length; index++)
        {
            if (content[index] == '\n')
            {
                line++;
            }
        }

        return line;
    }

}



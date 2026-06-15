using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.CircleCi;

public sealed partial class CircleCiAnalyzer : IRepositoryAnalyzer
{
    public string Id => "circleci";

    public string DisplayName => "CircleCI Security";

    public AnalysisCategory Category => AnalysisCategory.CiCd;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-CIRCLE001", "CircleCI orb version is not pinned", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "An orb is declared without a pinned version.", "Pin orb versions to avoid unexpected changes. Use @x.y.z notation."),
        new("TRUST-CIRCLE002", "CircleCI Docker executor image uses latest or no tag", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "A Docker executor image uses :latest or no tag.", "Pin Docker images to specific versions or digests."),
        new("TRUST-CIRCLE003", "CircleCI workspace persist stores repository root", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium,
            "Workspace persist uses root . or ~/project.", "Persist only build output directories."),
        new("TRUST-CIRCLE004", "CircleCI inline secret-looking environment variable", AnalysisCategory.Security, Severity.High, Confidence.Medium,
            "A literal secret-looking value is defined in a CircleCI environment block.", "Use CircleCI contexts or external secret management."),
        new("TRUST-CIRCLE005", "CircleCI remote Docker uses preview version", AnalysisCategory.CiCd, Severity.Low, Confidence.High,
            "setup_remote_docker explicitly selects the floating edge version.", "Use CircleCI's default stable Docker version or pin a supported production version."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "config.yml")
                     .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "config.yaml")))
        {
            // Only process .circleci config files
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
            if (!relativePath.Contains(".circleci/", StringComparison.OrdinalIgnoreCase) &&
                !relativePath.StartsWith(".circleci", StringComparison.OrdinalIgnoreCase))
                continue;

            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
                continue;

            var content = await File.ReadAllTextAsync(file, cancellationToken);

            CheckUnpinnedOrbs(content, relativePath, findings);
            CheckLatestDockerImage(content, relativePath, findings);
            CheckWorkspacePersistRoot(content, relativePath, findings);
            CheckInlineSecrets(content, relativePath, findings);
            CheckRemoteDockerPreviewVersion(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckUnpinnedOrbs(string content, string relativePath, List<Finding> findings)
    {
        foreach (var (line, lineNumber) in EnumerateBlockLines(content, "orbs"))
        {
            var match = OrbRefPattern().Match(line);
            if (!match.Success)
                continue;

            var orb = match.Groups["orb"].Value.TrimEnd();
            var atIdx = orb.LastIndexOf('@');
            if (atIdx < 0)
            {
                findings.Add(CreateFinding("TRUST-CIRCLE001", "Unpinned CircleCI orb",
                    Severity.Medium, relativePath, $"Orb '{orb}' has no pinned version.",
                    lineNumber));
            }
            else
            {
                var version = orb[(atIdx + 1)..].Trim();
                if (version is "volatile" or "dev" or "latest")
                {
                    findings.Add(CreateFinding("TRUST-CIRCLE001", "Floating CircleCI orb version",
                        Severity.Medium, relativePath, $"Orb '{orb}' uses floating version '@{version}'.",
                        lineNumber));
                }
            }
        }
    }

    private static void CheckLatestDockerImage(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in CircleDockerImagePattern().Matches(content))
        {
            var image = match.Groups["image"].Value.Trim();

            // Skip digest-pinned
            if (image.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
                continue;

            var lastSlash = image.LastIndexOf('/');
            var tagSeparator = image.LastIndexOf(':');
            if (tagSeparator <= lastSlash)
            {
                // No tag at all
                findings.Add(CreateFinding("TRUST-CIRCLE002", "Unpinned Docker image",
                    Severity.Medium, relativePath, $"Docker image '{image}' has no tag.",
                    GetLineNumber(content, match.Index)));
            }
            else
            {
                var tag = image[(tagSeparator + 1)..].Trim();
                if (tag.Equals("latest", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding("TRUST-CIRCLE002", "Unpinned Docker image",
                        Severity.Medium, relativePath, $"Docker image '{image}' uses :latest tag.",
                        GetLineNumber(content, match.Index)));
                }
            }
        }
    }

    private static void CheckWorkspacePersistRoot(string content, string relativePath, List<Finding> findings)
    {
        if (WorkspacePersistPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-CIRCLE003", "Broad workspace persist",
                Severity.Low, relativePath, "Workspace persists repository root. Narrow to build output.",
                GetLineNumber(content, content.IndexOf("persist_to_workspace", StringComparison.Ordinal)),
                Confidence.Medium));
        }
    }

    private static void CheckInlineSecrets(string content, string relativePath, List<Finding> findings)
    {
        foreach (var (line, lineNumber) in EnumerateBlockLines(content, "environment"))
        {
            var match = InlineSecretPattern().Match(line);
            if (!match.Success)
                continue;

            var key = match.Groups["key"].Value;
            var value = match.Groups["value"].Value;

            if (IsPlaceholder(value))
                continue;

            findings.Add(CreateFinding("TRUST-CIRCLE004", "Inline secret in CircleCI config",
                Severity.High, relativePath, $"Secret-like variable '{key}' has a literal value.",
                lineNumber,
                Confidence.Medium));
        }
    }

    private static void CheckRemoteDockerPreviewVersion(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in RemoteDockerEdgePattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-CIRCLE005", "Remote Docker uses preview version",
                Severity.Low, relativePath, "setup_remote_docker selects the floating edge version.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static bool IsPlaceholder(string value)
    {
        var lower = value.Trim('"', '\'').ToLowerInvariant();
        return lower.Contains("changeme") || lower.Contains("example") ||
               lower.Contains("dummy") || lower.Contains("placeholder") ||
               lower.Contains("${{") || lower.Contains("${") ||
               lower.Contains("<< pipeline.parameters") ||
               lower.StartsWith('$') ||
               lower.StartsWith('%');
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.CiCd, severity, confidence, title,
            [new Evidence("circleci", evidence, filePath, lineNumber)],
            new Recommendation("Review the CircleCI configuration and apply the recommended fix."));
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    private static IEnumerable<(string Line, int LineNumber)> EnumerateBlockLines(string content, string blockName)
    {
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!Regex.IsMatch(lines[i], $@"^\s*{Regex.Escape(blockName)}\s*:\s*$", RegexOptions.IgnoreCase))
                continue;

            var baseIndent = GetIndentation(lines[i]);
            for (var cursor = i + 1; cursor < lines.Length; cursor++)
            {
                if (string.IsNullOrWhiteSpace(lines[cursor]))
                    continue;

                if (GetIndentation(lines[cursor]) <= baseIndent)
                    break;

                yield return (lines[cursor], cursor + 1);
            }
        }
    }

    private static int GetIndentation(string line)
    {
        var count = 0;
        foreach (var c in line)
        {
            if (c == ' ') count++;
            else if (c == '\t') count += 4;
            else break;
        }

        return count;
    }

    [GeneratedRegex(@"^\s+(?:-\s+)?\w[\w-]*\s*:\s*(?<orb>[\w][\w.-]*/[\w][\w.-]*(?:@\S+)?)", RegexOptions.IgnoreCase)]
    private static partial Regex OrbRefPattern();

    [GeneratedRegex(@"image\s*:\s*(?<image>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex CircleDockerImagePattern();

    [GeneratedRegex(@"persist_to_workspace[\s\S]{0,100}root\s*:\s*(?:\.|~/project)", RegexOptions.IgnoreCase)]
    private static partial Regex WorkspacePersistPattern();

    [GeneratedRegex(@"(?m)^\s*(?<key>\w*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)\w*)\s*:\s*(?<value>\S+)")]
    private static partial Regex InlineSecretPattern();

    [GeneratedRegex(
        @"setup_remote_docker\s*:\s*(?:\r?\n)+\s+version\s*:\s*['""]?edge['""]?",
        RegexOptions.IgnoreCase)]
    private static partial Regex RemoteDockerEdgePattern();
}

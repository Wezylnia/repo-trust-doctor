using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.GitLabCi;

public sealed partial class GitLabCiAnalyzer : IRepositoryAnalyzer
{
    public string Id => "gitlab-ci";

    public string DisplayName => "GitLab CI Security";

    public AnalysisCategory Category => AnalysisCategory.CiCd;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-GLCI001", "GitLab CI uses remote includes", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "The pipeline configuration references remote include files.", "Remote includes may change without repository changes. Review their content and provenance."),
        new("TRUST-GLCI002", "GitLab CI interpolates CI variables in shell", AnalysisCategory.CiCd, Severity.High, Confidence.Medium,
            "A script block interpolates a CI/CD variable inline.", "Avoid direct shell interpolation of CI variables. Pass them as environment variables instead."),
        new("TRUST-GLCI003", "GitLab CI uses latest image tag", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "A job uses an image or service with the latest tag.", "Pin container images to specific versions or digests for reproducible CI runs."),
        new("TRUST-GLCI004", "GitLab CI uses deprecated only/except", AnalysisCategory.CiCd, Severity.Low, Confidence.High,
            "The pipeline uses deprecated only/except keywords instead of rules.", "Migrate to rules: syntax for better control and readability."),
        new("TRUST-GLCI005", "GitLab CI service uses privileged Docker-in-Docker", AnalysisCategory.CiCd, Severity.High, Confidence.Medium,
            "A service image uses Docker-in-Docker or privileged mode is enabled.", "Avoid privileged Docker-in-Docker for untrusted pipelines; prefer rootless builders, Kaniko/BuildKit with least privilege, or isolated runners."),
        new("TRUST-GLCI006", "GitLab CI cache uses broad repository path", AnalysisCategory.CiCd, Severity.Medium, Confidence.Medium,
            "A cache block specifies an overly broad path.", "Narrow cache paths to build output directories such as target/, node_modules/, or .gradle/."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, ".gitlab-ci.yml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

            CheckRemoteIncludes(content, relativePath, findings);
            CheckCiVariableInjection(content, relativePath, findings);
            CheckLatestImageTags(content, relativePath, findings);
            CheckDeprecatedOnlyExcept(content, relativePath, findings);
            CheckDockerInDocker(content, relativePath, findings);
            CheckBroadCachePaths(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckRemoteIncludes(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in RemoteIncludePattern().Matches(content))
        {
            var url = match.Groups["url"].Value;
            findings.Add(CreateFinding("TRUST-GLCI001",
                "GitLab CI uses remote includes",
                Severity.Medium,
                relativePath,
                $"Remote include references '{url}'. Remote includes may change without repository changes.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckCiVariableInjection(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!ScriptBlockPattern().IsMatch(line))
            {
                continue;
            }

            // Scan subsequent indented lines for CI variable injection
            var baseIndent = GetIndentation(line);
            for (int j = i + 1; j < lines.Length; j++)
            {
                var subLine = lines[j];
                if (string.IsNullOrWhiteSpace(subLine))
                {
                    continue;
                }
                var subIndent = GetIndentation(subLine);
                if (subIndent <= baseIndent)
                {
                    break;
                }
                if (CiVariablePattern().IsMatch(subLine))
                {
                    findings.Add(CreateFinding("TRUST-GLCI002",
                        "GitLab CI interpolates CI variables in shell",
                        Severity.High,
                        relativePath,
                        "A script block interpolates CI/CD variables inline. Use environment variables instead.",
                        j + 1,
                        Confidence.Medium));
                    break;
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
            else if (c == '\t') count += 2;
            else break;
        }
        return count;
    }

    private static void CheckLatestImageTags(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in LatestImagePattern().Matches(content))
        {
            var image = match.Groups["image"].Value;
            findings.Add(CreateFinding("TRUST-GLCI003",
                "GitLab CI uses latest image tag",
                Severity.Medium,
                relativePath,
                $"Image '{image}' uses an unpinned tag.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckDeprecatedOnlyExcept(string content, string relativePath, List<Finding> findings)
    {
        if (DeprecatedOnlyExceptPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-GLCI004",
                "GitLab CI uses deprecated only/except",
                Severity.Low,
                relativePath,
                "The pipeline uses deprecated 'only' or 'except' keywords. Migrate to rules: for better control."));
        }
    }

    private static void CheckDockerInDocker(string content, string relativePath, List<Finding> findings)
    {
        // Detect docker:dind as a service image
        if (DockerDinDPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-GLCI005",
                "GitLab CI uses Docker-in-Docker service",
                Severity.High,
                relativePath,
                "A service image enables Docker-in-Docker. Prefer rootless builders or Kaniko for untrusted pipelines.",
                GetLineNumber(content, content.IndexOf("dind", StringComparison.Ordinal)),
                Confidence.Medium));
        }

        // Check for privileged Docker variables
        foreach (Match match in PrivilegedVariablePattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-GLCI005",
                "GitLab CI uses privileged mode",
                Severity.High,
                relativePath,
                "Privileged mode (empty DOCKER_TLS_CERTDIR or DOCKER_HOST) may allow escape from container isolation.",
                GetLineNumber(content, match.Index),
                Confidence.Medium));
        }
    }

    private static void CheckBroadCachePaths(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in BroadCachePattern().Matches(content))
        {
            var cachePath = match.Groups["path"].Value.Trim();
            // Flag paths that are too broad: ., ./*, *, or have no subdirectory specificity
            var normalized = cachePath.TrimEnd('/', '*', '.');
            if (string.IsNullOrEmpty(normalized) || normalized is "." or "..")
            {
                findings.Add(CreateFinding("TRUST-GLCI006",
                    "GitLab CI cache path is too broad",
                    Severity.Medium,
                    relativePath,
                    $"Cache path '{cachePath}' is overly broad. Narrow it to build output directories.",
                    GetLineNumber(content, match.Index),
                    Confidence.Medium));
            }
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.CiCd, severity, confidence, title,
            [new Evidence("gitlab-ci", evidence, filePath, lineNumber)],
            new Recommendation("Review the GitLab CI configuration and apply the recommended fix."));
    }

    private static string[] SplitLines(string content) =>
        content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
        {
            if (content[i] == '\n') line++;
        }
        return line;
    }

    [GeneratedRegex(@"include:\s*.*remote:\s*['""](?<url>[^'""]+)['""]", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteIncludePattern();

    [GeneratedRegex(@"^\s*(?:-\s+)?(?:script|before_script|after_script)\s*:")]
    private static partial Regex ScriptBlockPattern();

    [GeneratedRegex(@"\$(?:CI_[A-Z_]+|\{[A-Z_]+\})", RegexOptions.IgnoreCase)]
    private static partial Regex CiVariablePattern();

    [GeneratedRegex(@"(?:image|services):\s*['""]?(?<image>[^'""\s]+:latest)['""]?", RegexOptions.IgnoreCase)]
    private static partial Regex LatestImagePattern();

    [GeneratedRegex(@"(?m)^\s*(only|except)\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex DeprecatedOnlyExceptPattern();

    [GeneratedRegex(@"(?m)^\s*(?:DOCKER_TLS_CERTDIR|CI_DOCKER_TLS_CERTDIR|DOCKER_HOST)\s*:\s*""?\s*""?\s*$|^\s*privileged\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex PrivilegedVariablePattern();

    [GeneratedRegex(@"docker:(?:dind|[\d.]+-dind)", RegexOptions.IgnoreCase)]
    private static partial Regex DockerDinDPattern();

    [GeneratedRegex(@"(?m)^\s+paths\s*:\s*\n(\s+-\s*(?<path>[^\n]+))", RegexOptions.IgnoreCase)]
    private static partial Regex BroadCachePattern();
}

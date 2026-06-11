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
}

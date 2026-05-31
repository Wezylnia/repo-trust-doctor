using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.GitHubActions;

public sealed partial class GitHubActionsBasicAnalyzer : IRepositoryAnalyzer
{
    public string Id => "github-actions-basic";

    public string DisplayName => "GitHub Actions Basic Security";

    public AnalysisCategory Category => AnalysisCategory.CiCd;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var workflowRoot = Path.Combine(context.RepositoryPath, ".github", "workflows");
        if (!Directory.Exists(workflowRoot))
        {
            return AnalyzerResult.Completed([]);
        }

        var findings = new List<Finding>();
        foreach (var file in Directory.EnumerateFiles(workflowRoot, "*.*", SearchOption.TopDirectoryOnly)
                     .Where(file => file.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

            if (!PermissionsPattern().IsMatch(content))
            {
                AddFinding(findings, "TRUST-GHA001", "Workflow permissions are not declared", Severity.Medium, "Declare least-privilege workflow permissions explicitly.", relativePath, "No top-level or job-level permissions key was found.");
            }

            if (WriteAllPattern().IsMatch(content))
            {
                AddFinding(findings, "TRUST-GHA002", "Workflow uses permissions: write-all", Severity.High, "Replace write-all with the narrowest permissions required by each job.", relativePath, "permissions: write-all was found.");
            }

            if (PullRequestTargetPattern().IsMatch(content))
            {
                AddFinding(findings, "TRUST-GHA003", "Workflow uses pull_request_target", Severity.High, "Review pull_request_target usage carefully and avoid running untrusted pull request code with repository privileges.", relativePath, "pull_request_target trigger was found.");
            }

            if (CurlPipeShellPattern().IsMatch(content) || WgetPipeShellPattern().IsMatch(content))
            {
                AddFinding(findings, "TRUST-GHA004", "Workflow pipes downloaded scripts into a shell", Severity.High, "Download scripts separately, verify integrity, and avoid piping remote content directly into a shell.", relativePath, "A curl/wget pipe-to-shell pattern was found.");
            }

            foreach (Match match in UsesPattern().Matches(content))
            {
                var action = match.Groups["action"].Value;
                var version = match.Groups["version"].Value;
                if (!IsPinnedToSha(version) && !action.StartsWith("./", StringComparison.Ordinal))
                {
                    AddFinding(findings, "TRUST-GHA005", "Third-party action is not pinned by SHA", Severity.Medium, "Pin third-party GitHub Actions to a full commit SHA.", relativePath, $"Action '{action}@{version}' is not pinned to a full commit SHA.");
                }
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static bool IsPinnedToSha(string value) => ShaPattern().IsMatch(value);

    private static void AddFinding(List<Finding> findings, string ruleId, string title, Severity severity, string recommendation, string filePath, string evidence)
    {
        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.CiCd,
            severity,
            Confidence.High,
            title,
            [new Evidence("workflow", evidence, filePath)],
            new Recommendation(recommendation)));
    }

    [GeneratedRegex(@"(?m)^\s*permissions\s*:")]
    private static partial Regex PermissionsPattern();

    [GeneratedRegex(@"(?mi)^\s*permissions\s*:\s*write-all\s*$")]
    private static partial Regex WriteAllPattern();

    [GeneratedRegex(@"(?mi)pull_request_target")]
    private static partial Regex PullRequestTargetPattern();

    [GeneratedRegex(@"(?mi)curl\b.+\|\s*(bash|sh)")]
    private static partial Regex CurlPipeShellPattern();

    [GeneratedRegex(@"(?mi)wget\b.+\|\s*(bash|sh)")]
    private static partial Regex WgetPipeShellPattern();

    [GeneratedRegex(@"uses\s*:\s*(?<action>[^@\s]+)@(?<version>[^\s#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex UsesPattern();

    [GeneratedRegex(@"^[a-f0-9]{40}$", RegexOptions.IgnoreCase)]
    private static partial Regex ShaPattern();
}

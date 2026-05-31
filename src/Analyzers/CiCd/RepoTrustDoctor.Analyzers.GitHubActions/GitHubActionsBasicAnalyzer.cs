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

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-GHA001", "Workflow permissions are not declared", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "No top-level or job-level permissions key was found in the workflow.", "Declare least-privilege workflow permissions explicitly."),
        new("TRUST-GHA002", "Workflow uses permissions: write-all", AnalysisCategory.CiCd, Severity.High, Confidence.High, "The workflow declares permissions: write-all.", "Replace write-all with the narrowest permissions required by each job."),
        new("TRUST-GHA003", "Workflow uses pull_request_target", AnalysisCategory.CiCd, Severity.High, Confidence.High, "The workflow uses pull_request_target trigger.", "Review pull_request_target usage carefully and avoid running untrusted pull request code with repository privileges."),
        new("TRUST-GHA004", "Workflow pipes downloaded scripts into a shell", AnalysisCategory.CiCd, Severity.High, Confidence.High, "A curl/wget pipe-to-shell pattern was found.", "Download scripts separately, verify integrity, and avoid piping remote content directly into a shell."),
        new("TRUST-GHA005", "Third-party action is not pinned by SHA", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "A third-party action is referenced by tag instead of full commit SHA.", "Pin third-party GitHub Actions to a full commit SHA."),
        new("TRUST-GHA006", "Workflow uses self-hosted runner", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "The workflow runs on a self-hosted runner.", "Ensure self-hosted runners are isolated and do not run untrusted pull request code."),
        new("TRUST-GHA007", "Checkout may persist credentials", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium, "The workflow uses actions/checkout without setting persist-credentials to false.", "Set persist-credentials: false to avoid exposing github token to subsequent steps."),
        new("TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "The workflow interpolates github.event, github.head_ref, or github.ref_name directly inside a run block.", "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var workflowRoot = Path.Combine(context.RepositoryPath, ".github", "workflows");
        if (!Directory.Exists(workflowRoot))
        {
            return AnalyzerResult.Completed([]);
        }

        var findings = new List<Finding>();
        foreach (var file in RepositoryFileSystem.EnumerateFiles(workflowRoot, "*.*", SearchOption.TopDirectoryOnly)
                     .Where(file => file.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

            if (!PermissionsPattern().IsMatch(content))
            {
                AddFinding(findings, "TRUST-GHA001", "Workflow permissions are not declared", Severity.Medium, "Declare least-privilege workflow permissions explicitly.", relativePath, "No top-level or job-level permissions key was found.");
            }

            if (WriteAllPattern().Match(content) is { Success: true } writeAllMatch)
            {
                AddFinding(findings, "TRUST-GHA002", "Workflow uses permissions: write-all", Severity.High, "Replace write-all with the narrowest permissions required by each job.", relativePath, "permissions: write-all was found.", GetLineNumber(content, writeAllMatch.Index));
            }

            if (PullRequestTargetPattern().Match(content) is { Success: true } pullRequestTargetMatch)
            {
                AddFinding(findings, "TRUST-GHA003", "Workflow uses pull_request_target", Severity.High, "Review pull_request_target usage carefully and avoid running untrusted pull request code with repository privileges.", relativePath, "pull_request_target trigger was found.", GetLineNumber(content, pullRequestTargetMatch.Index));
            }

            var curlPipeShellMatch = CurlPipeShellPattern().Match(content);
            var wgetPipeShellMatch = WgetPipeShellPattern().Match(content);
            if (curlPipeShellMatch.Success || wgetPipeShellMatch.Success)
            {
                var match = curlPipeShellMatch.Success ? curlPipeShellMatch : wgetPipeShellMatch;
                AddFinding(findings, "TRUST-GHA004", "Workflow pipes downloaded scripts into a shell", Severity.High, "Download scripts separately, verify integrity, and avoid piping remote content directly into a shell.", relativePath, "A curl/wget pipe-to-shell pattern was found.", GetLineNumber(content, match.Index));
            }

            foreach (Match match in UsesPattern().Matches(content))
            {
                var action = match.Groups["action"].Value;
                var version = match.Groups["version"].Value;
                if (!IsPinnedToSha(version) && !action.StartsWith("./", StringComparison.Ordinal))
                {
                    AddFinding(findings, "TRUST-GHA005", "Third-party action is not pinned by SHA", Severity.Medium, "Pin third-party GitHub Actions to a full commit SHA.", relativePath, $"Action '{action}@{version}' is not pinned to a full commit SHA.", GetLineNumber(content, match.Index));
                }
            }

            if (SelfHostedPattern().Match(content) is { Success: true } selfHostedMatch)
            {
                AddFinding(findings, "TRUST-GHA006", "Workflow uses self-hosted runner", Severity.Medium, "Ensure self-hosted runners are isolated and do not run untrusted pull request code.", relativePath, "self-hosted runner was found.", GetLineNumber(content, selfHostedMatch.Index));
            }

            var lines = content.Split(['\r', '\n'], StringSplitOptions.None);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (UsesCheckoutPattern().IsMatch(line))
                {
                    var hasPersistCredentialsFalse = false;
                    var checkLimit = Math.Min(i + 9, lines.Length);
                    for (int j = i + 1; j < checkLimit; j++)
                    {
                        if (PersistCredentialsFalsePattern().IsMatch(lines[j]))
                        {
                            hasPersistCredentialsFalse = true;
                            break;
                        }
                    }

                    if (!hasPersistCredentialsFalse)
                    {
                        AddFinding(findings, "TRUST-GHA007", "Checkout may persist credentials", Severity.Low, "Set persist-credentials: false when checkout is only used for building or testing.", relativePath, "actions/checkout is used without persist-credentials: false.", i + 1);
                    }
                }
            }

            CheckShellInjection(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckShellInjection(string content, string relativePath, List<Finding> findings)
    {
        var lines = content.Split(['\r', '\n'], StringSplitOptions.None);
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
                        AddFinding(findings, "TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", Severity.High, "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead.", relativePath, "Potential shell injection found in run block.", i + 1);
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
                            AddFinding(findings, "TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", Severity.High, "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead.", relativePath, "Potential shell injection found in multiline run block.", j + 1);
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

    private static bool IsPinnedToSha(string value) => ShaPattern().IsMatch(value);

    private static void AddFinding(List<Finding> findings, string ruleId, string title, Severity severity, string recommendation, string filePath, string evidence, int? lineNumber = null)
    {
        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.CiCd,
            severity,
            Confidence.High,
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

    [GeneratedRegex(@"(?mi)(?:^\s*runs-on\s*:\s*(?:['""]*self-hosted['""]*|\[[^\]]*\bself-hosted\b[^\]]*\])|^\s*-\s*['""]*self-hosted['""]*\s*$)")]
    private static partial Regex SelfHostedPattern();

    [GeneratedRegex(@"\buses\s*:\s*actions/checkout@", RegexOptions.IgnoreCase)]
    private static partial Regex UsesCheckoutPattern();

    [GeneratedRegex(@"\bpersist-credentials\s*:\s*['""]?false['""]?", RegexOptions.IgnoreCase)]
    private static partial Regex PersistCredentialsFalsePattern();

    [GeneratedRegex(@"^\s*(?:-\s*)?run\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex RunBlockPattern();

    [GeneratedRegex(@"\$\{\{\s*github\.(?:event\.|head_ref\b|ref_name\b)", RegexOptions.IgnoreCase)]
    private static partial Regex InjectionPattern();
}

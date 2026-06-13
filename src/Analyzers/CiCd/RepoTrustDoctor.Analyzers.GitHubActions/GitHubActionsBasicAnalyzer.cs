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
        new("TRUST-GHA005", "External action is not pinned by SHA", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "An external GitHub Action is referenced by tag instead of full commit SHA.", "Pin external GitHub Actions to a full commit SHA."),
        new("TRUST-GHA006", "Workflow uses self-hosted runner", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "The workflow runs on a self-hosted runner.", "Ensure self-hosted runners are isolated and do not run untrusted pull request code."),
        new("TRUST-GHA007", "Checkout may persist credentials", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium, "The workflow uses actions/checkout without setting persist-credentials to false.", "Set persist-credentials: false to avoid exposing github token to subsequent steps."),
        new("TRUST-GHA008", "Workflow may interpolate GitHub event data in shell", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "The workflow interpolates github.event, github.head_ref, or github.ref_name directly inside a run block.", "Avoid direct inline shell interpolation of event data. Pass event data as environment variables instead."),
        new("TRUST-GHA009", "Release workflow may publish without test dependency", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "The workflow appears to publish or release artifacts without a visible test dependency.", "Make release or publish jobs depend on a test or CI job before publishing artifacts or packages."),
        new("TRUST-GHA010", "Workflow uploads overly broad artifact path", AnalysisCategory.CiCd, Severity.Medium, Confidence.Medium, "The workflow uploads an artifact from an overly broad path such as the repository root.", "Upload only specific build outputs and avoid broad artifact paths that may include source, secrets, or temporary files."),
        new("TRUST-GHA011", "Workflow does not restrict GITHUB_TOKEN scope", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "The workflow declares permissions but does not restrict GITHUB_TOKEN to read-only or specific scopes.", "Set per-job permissions to restrict GITHUB_TOKEN to the minimum required scope."),
        new("TRUST-GHA012", "Workflow deploys to an unprotected environment", AnalysisCategory.CiCd, Severity.Medium, Confidence.Medium, "The workflow targets an environment without visible protection rules or required reviewers.", "Add environment protection rules with required reviewers for production deployments."),
        new("TRUST-GHA013", "Workflow may contain hardcoded secret in step env", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "A step sets an environment variable that contains a secret-like value inline.", "Use GitHub Secrets instead of inline values for credentials and tokens."),
        new("TRUST-GHA014", "Workflow may interpolate matrix values in shell", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "The workflow interpolates a matrix variable directly inside a run block.", "Avoid direct inline shell interpolation of matrix values. Pass matrix values as environment variables instead."),
        new("TRUST-GHA015", "pull_request_target workflow exposes secrets to untrusted code", AnalysisCategory.CiCd, Severity.High, Confidence.Medium, "A pull_request_target workflow checks out PR code or uses secrets in a risky context.", "Avoid checking out untrusted PR code in pull_request_target workflows. Use a separate untrusted workflow for PR validation."),
        new("TRUST-GHA016", "Workflow-level write permissions are overly broad", AnalysisCategory.CiCd, Severity.Medium, Confidence.Medium, "Top-level permissions grant contents:write, packages:write, or actions:write.", "Reduce permissions to least privilege per job. Avoid broad write at the workflow level."),
        new("TRUST-GHA017", "Workflow uses overly broad cache path", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium, "An actions/cache step caches an overly broad path.", "Narrow cache paths to specific package directories."),
        new("TRUST-GHA018", "Workflow job container or service image uses latest", AnalysisCategory.CiCd, Severity.Medium, Confidence.High, "A job container or service image uses :latest or no tag.", "Pin container images to specific versions or digests."),
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
                    AddFinding(findings, "TRUST-GHA005", "External action is not pinned by SHA", Severity.Medium, "Pin external GitHub Actions to a full commit SHA.", relativePath, $"Action '{action}@{version}' is not pinned to a full commit SHA.", GetLineNumber(content, match.Index));
                }
            }

            if (SelfHostedPattern().Match(content) is { Success: true } selfHostedMatch)
            {
                AddFinding(findings, "TRUST-GHA006", "Workflow uses self-hosted runner", Severity.Medium, "Ensure self-hosted runners are isolated and do not run untrusted pull request code.", relativePath, "self-hosted runner was found.", GetLineNumber(content, selfHostedMatch.Index));
            }

            var lines = SplitLines(content);
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
                        AddFinding(findings, "TRUST-GHA007", "Checkout may persist credentials", Severity.Low, "Set persist-credentials: false when checkout is only used for building or testing.", relativePath, "actions/checkout is used without persist-credentials: false.", i + 1, Confidence.Medium);
                    }
                }
            }

            CheckShellInjection(content, relativePath, findings);
            CheckReleaseWorkflowDependency(content, relativePath, findings);
            CheckArtifactUploadPaths(content, relativePath, findings);
            CheckTokenScope(content, relativePath, findings);
            CheckHardcodedSecretsInEnv(content, relativePath, findings);
            CheckMatrixInjection(content, relativePath, findings);
            CheckPrTargetSecretsExposure(content, relativePath, findings);
            CheckWorkflowWritePermissions(content, relativePath, findings);
            CheckBroadCachePaths(content, relativePath, findings);
            CheckJobContainerLatest(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

}


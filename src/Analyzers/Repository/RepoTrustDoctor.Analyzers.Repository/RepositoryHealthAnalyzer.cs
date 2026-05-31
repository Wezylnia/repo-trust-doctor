using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Repository;

public sealed class RepositoryHealthAnalyzer : IRepositoryAnalyzer
{
    public string Id => "repository-health";

    public string DisplayName => "Repository Health";

    public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-REPO001", "README is missing", AnalysisCategory.RepositoryHealth, Severity.Medium, Confidence.High, "The repository does not contain a README file.", "Add a README that explains the project purpose, installation, and basic usage."),
        new("TRUST-REPO002", "LICENSE is missing", AnalysisCategory.RepositoryHealth, Severity.High, Confidence.High, "The repository does not contain a LICENSE file.", "Add a license file so users can understand whether and how the project can be used."),
        new("TRUST-REPO003", "SECURITY.md is missing", AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.High, "The repository does not contain a SECURITY.md file.", "Add SECURITY.md to explain how vulnerabilities should be reported."),
        new("TRUST-REPO004", "CONTRIBUTING.md is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CONTRIBUTING.md file.", "Add contribution guidance for maintainers and contributors."),
        new("TRUST-REPO005", "CODE_OF_CONDUCT.md is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CODE_OF_CONDUCT.md file.", "Add a code of conduct if the project accepts community contribution."),
        new("TRUST-REPO006", "CODEOWNERS is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CODEOWNERS file.", "Add CODEOWNERS when ownership review should be explicit."),
        new("TRUST-REPO007", "Issue template is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain an issue template.", "Add issue templates to collect enough information from users."),
        new("TRUST-REPO008", "Pull request template is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a pull request template.", "Add a pull request template to make review expectations clear."),
        new("TRUST-REPO009", "CHANGELOG is missing", AnalysisCategory.RepositoryHealth, Severity.Info, Confidence.High, "The repository does not contain a CHANGELOG file.", "Add a changelog to document user-facing changes in each release."),
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        CheckRequiredFile(context.RepositoryPath, ["README.md", "README"], "TRUST-REPO001", "README is missing", "Add a README that explains the project purpose, installation, and basic usage.", findings, Severity.Medium);
        CheckRequiredFile(context.RepositoryPath, ["LICENSE", "LICENSE.md"], "TRUST-REPO002", "LICENSE is missing", "Add a license file so users can understand whether and how the project can be used.", findings, Severity.High);
        CheckRequiredFile(context.RepositoryPath, ["SECURITY.md", ".github/SECURITY.md"], "TRUST-REPO003", "SECURITY.md is missing", "Add SECURITY.md to explain how vulnerabilities should be reported.", findings, Severity.Low);
        CheckRequiredFile(context.RepositoryPath, ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"], "TRUST-REPO004", "CONTRIBUTING.md is missing", "Add contribution guidance for maintainers and contributors.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, ["CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md"], "TRUST-REPO005", "CODE_OF_CONDUCT.md is missing", "Add a code of conduct if the project accepts community contribution.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/CODEOWNERS", "CODEOWNERS"], "TRUST-REPO006", "CODEOWNERS is missing", "Add CODEOWNERS when ownership review should be explicit.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/ISSUE_TEMPLATE", ".github/ISSUE_TEMPLATE.md"], "TRUST-REPO007", "Issue template is missing", "Add issue templates to collect enough information from users.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, [".github/PULL_REQUEST_TEMPLATE.md", "PULL_REQUEST_TEMPLATE.md"], "TRUST-REPO008", "Pull request template is missing", "Add a pull request template to make review expectations clear.", findings, Severity.Info);
        CheckRequiredFile(context.RepositoryPath, ["CHANGELOG.md", "CHANGELOG", "HISTORY.md", "RELEASES.md"], "TRUST-REPO009", "CHANGELOG is missing", "Add a changelog to document user-facing changes in each release.", findings, Severity.Info);

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static void CheckRequiredFile(
        string root,
        IReadOnlyList<string> relativePaths,
        string ruleId,
        string title,
        string recommendation,
        List<Finding> findings,
        Severity severity)
    {
        if (relativePaths.Any(path => File.Exists(Path.Combine(root, path)) || Directory.Exists(Path.Combine(root, path))))
        {
            return;
        }

        findings.Add(new Finding(
            ruleId,
            title,
            AnalysisCategory.RepositoryHealth,
            severity,
            Confidence.High,
            title,
            [new Evidence("file-missing", $"None of the expected paths exist: {string.Join(", ", relativePaths)}")],
            new Recommendation(recommendation)));
    }
}

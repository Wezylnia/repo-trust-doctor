using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitHubActionsBasicAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReportsUnpinnedThirdPartyAction()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA005");
    }
}

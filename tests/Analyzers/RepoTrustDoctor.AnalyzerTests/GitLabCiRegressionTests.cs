using RepoTrustDoctor.Analyzers.GitLabCi;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitLabCiRegressionTests
{
    private static readonly GitLabCiAnalyzer Analyzer = new();

    [Fact]
    public async Task InlineScriptEvalWithCiVariableReportsInjection()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        build:
          script: eval "$CI_DEPLOY_COMMAND"
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GLCI002");
    }

    [Fact]
    public async Task LatestServiceInListReportsUnpinnedImage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        test:
          image: node:20
          services:
            - postgres:latest
          script:
            - npm test
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GLCI003");
    }
}

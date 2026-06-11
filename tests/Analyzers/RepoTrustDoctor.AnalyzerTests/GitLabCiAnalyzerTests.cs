using RepoTrustDoctor.Analyzers.GitLabCi;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitLabCiAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsRemoteIncludes()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        include:
          - remote: 'https://example.com/ci-templates.yml'
        stages:
          - build
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsCiVariableInjection()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          script:
            - echo "Deploying to $CI_ENVIRONMENT_URL"
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsLatestImageTag()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - test
        test:
          image: node:latest
          script:
            - npm test
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsDeprecatedOnlyExcept()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          only:
            - main
          script:
            - make
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI004");
    }

    [Fact]
    public async Task AnalyzeAsync_NoGitLabCiFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_PinnedImage_NoLatestFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - test
        test:
          image: node:20.11
          script:
            - npm test
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GLCI003");
    }

    [Fact]
    public async Task AnalyzeAsync_SafeScriptWithoutCiVariables_NoInjectionFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          script:
            - echo "Building app"
            - make build
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GLCI002");
    }

    [Fact]
    public async Task AnalyzeAsync_RulesInsteadOfOnlyExcept_NoDeprecatedFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          rules:
            - if: '$CI_COMMIT_BRANCH == "main"'
          script:
            - make
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GLCI004");
    }
}

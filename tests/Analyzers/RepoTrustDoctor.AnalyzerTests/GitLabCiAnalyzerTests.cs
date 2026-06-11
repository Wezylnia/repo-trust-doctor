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
    // ── GLCI005: Docker-in-Docker ──────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsDockerInDockerService()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          image: alpine:3.20
          services:
            - docker:dind
          script:
            - docker build -t app .
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI005");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsPrivilegedMode()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        variables:
          DOCKER_TLS_CERTDIR: ""
        stages:
          - build
        build:
          image: alpine:3.20
          script:
            - docker build -t app .
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI005");
    }

    [Fact]
    public async Task AnalyzeAsync_NonDinDService_NoGLCI005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - test
        test:
          image: node:20.11
          services:
            - postgres:16
          script:
            - npm test
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GLCI005");
    }

    // ── GLCI006: Broad cache path ──────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsBroadCachePath()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          image: node:20.11
          cache:
            paths:
              - .
          script:
            - npm run build
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI006");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsGlobCachePath()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          image: node:20.11
          cache:
            paths:
              - ./*
          script:
            - npm run build
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GLCI006");
    }

    [Fact]
    public async Task AnalyzeAsync_NarrowCachePath_NoGLCI006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitlab-ci.yml"), """
        stages:
          - build
        build:
          image: node:20.11
          cache:
            paths:
              - node_modules/
          script:
            - npm run build
        """);

        var analyzer = new GitLabCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GLCI006");
    }}

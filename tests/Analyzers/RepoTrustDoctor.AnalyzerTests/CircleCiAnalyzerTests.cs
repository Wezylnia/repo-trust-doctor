using RepoTrustDoctor.Analyzers.CircleCi;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CircleCiAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsUnpinnedOrb()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        orbs:
          node: circleci/node
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-CIRCLE001");
    }

    [Fact]
    public async Task AnalyzeAsync_PinnedOrb_NoCIRCLE001()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        orbs:
          node: circleci/node@5.1.0
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE001");
    }

    [Fact]
    public async Task AnalyzeAsync_DockerImageReferenceIsNotTreatedAsOrb()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            docker:
              - image: cimg/node:20.11
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsLatestDockerImage()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            docker:
              - image: cimg/node:latest
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-CIRCLE002");
    }

    [Fact]
    public async Task AnalyzeAsync_PinnedDockerImage_NoCIRCLE002()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            docker:
              - image: cimg/node:20.11
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE002");
    }

    [Fact]
    public async Task AnalyzeAsync_RegistryPortWithoutTag_ReportsCIRCLE002()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            docker:
              - image: registry.example:5000/team/service
        """);

        var result = await new CircleCiAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CIRCLE002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsBroadWorkspacePersist()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            steps:
              - persist_to_workspace:
                  root: .
                  paths: ["."]
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-CIRCLE003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsInlineSecret()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeSecret = "sk-" + "realvalue123456";
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), $"""
        jobs:
          build:
            environment:
              API_KEY: {fakeSecret}
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-CIRCLE004");
    }

    [Fact]
    public async Task AnalyzeAsync_PlaceholderSecret_NoCIRCLE004()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            environment:
              API_KEY: changeme
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE004");
    }

    [Fact]
    public async Task AnalyzeAsync_SecretLikeParameterOutsideEnvironment_NoCIRCLE004()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        parameters:
          API_KEY:
            type: string
            default: sk-realvalue123456
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE004");
    }

    [Fact]
    public async Task AnalyzeAsync_DefaultRemoteDockerVersion_NoCIRCLE005()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            steps:
              - setup_remote_docker
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-CIRCLE005");
    }

    [Fact]
    public async Task AnalyzeAsync_EdgeRemoteDockerVersion_ReportsCIRCLE005()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, ".circleci"));
        File.WriteAllText(Path.Combine(fixture.Path, ".circleci", "config.yml"), """
        jobs:
          build:
            steps:
              - setup_remote_docker:
                  version: edge
        """);

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-CIRCLE005");
    }

    [Fact]
    public async Task AnalyzeAsync_NoCircleCiFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new CircleCiAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}

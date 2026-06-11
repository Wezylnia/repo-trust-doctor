using RepoTrustDoctor.Analyzers.AzurePipelines;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class AzurePipelinesAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsPrVariableInScript()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - script: echo "Building $(System.PullRequest.SourceBranch)"
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP001");
    }

    [Fact]
    public async Task AnalyzeAsync_SafeScriptWithoutPrVariables_NoAZP001()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - script: echo "Just building"
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsPersistCredentials()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - checkout: self
          persistCredentials: true
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP002");
    }

    [Fact]
    public async Task AnalyzeAsync_PersistCredentialsOutsideCheckout_NoAZP002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        variables:
          persistCredentials: true
        steps:
        - checkout: self
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP002");
    }

    [Fact]
    public async Task AnalyzeAsync_PersistCredentialsFalse_NoAZP002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - checkout: self
          persistCredentials: false
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsLatestContainerImage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        container:
          image: ubuntu:latest
        steps:
        - script: echo hello
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP003");
    }

    [Fact]
    public async Task AnalyzeAsync_DigestPinnedImage_NoAZP003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        container:
          image: ubuntu@sha256:abc123def456
        steps:
        - script: echo hello
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsSelfHostedPool()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        pool: MyPrivateAgents
        steps:
        - script: echo hello
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP004");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsSelfHostedPoolWhenAnotherJobUsesVmImage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        jobs:
        - job: hosted
          pool:
            vmImage: ubuntu-latest
        - job: private
          pool:
            name: private-linux
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP004");
    }

    [Fact]
    public async Task AnalyzeAsync_VmImagePool_NoAZP004()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        pool:
          vmImage: ubuntu-latest
        steps:
        - script: echo hello
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP004");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsBroadArtifactPath()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - task: PublishBuildArtifacts@1
          inputs:
            PathtoPublish: .
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP005");
    }

    [Fact]
    public async Task AnalyzeAsync_NarrowArtifactPath_NoAZP005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "azure-pipelines.yml"), """
        steps:
        - task: PublishBuildArtifacts@1
          inputs:
            PathtoPublish: dist
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-AZP005");
    }

    [Fact]
    public async Task AnalyzeAsync_NoAzurePipelineFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_AzurePipelinesDirectoryFile_IsScanned()
    {
        using var fixture = TemporaryRepository.Create();
        var pipelineDir = Path.Combine(fixture.Path, ".azure", "pipelines");
        Directory.CreateDirectory(pipelineDir);
        File.WriteAllText(Path.Combine(pipelineDir, "release.yml"), """
        steps:
        - script: echo "$(Build.SourceBranchName)"
        """);

        var analyzer = new AzurePipelinesAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-AZP001");
    }
}

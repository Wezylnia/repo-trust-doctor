using RepoTrustDoctor.Analyzers.DockerCompose;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DockerComposeAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsPrivilegedContainer()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            privileged: true
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsHostNetwork()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            network_mode: host
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP002");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsHostVolumeMount()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsBroadPortExposure()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            ports:
              - "0.0.0.0:8080:80"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP004");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsSecretInEnvironment()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            environment:
              - PASSWORD=supersecret
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP005");
    }

    [Fact]
    public async Task AnalyzeAsync_NoComposeFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }
}

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
              - /var/log/app:/logs
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-COMP003");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Contains("default read-write mode", finding.Evidence[0].Message);
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsQuotedHostVolumeMount()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - "/var/log/app:/logs:ro"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-COMP003");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Contains("ro", finding.Evidence[0].Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnalyzeAsync_ShortSyntaxReadWriteHostVolumeIsMediumSeverity()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - "/var/log/app:/logs:rw"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-COMP003");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Contains("rw", finding.Evidence[0].Message, StringComparison.OrdinalIgnoreCase);
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
    public async Task AnalyzeAsync_DetectsDefaultBroadPortExposure()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            ports:
              - "8080:80"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP004");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportBroadPortExposureInDevelopmentComposeFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var composePath = Path.Combine(fixture.Path, "devenv", "docker", "blocks", "prometheus", "docker-compose.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(composePath)!);
        File.WriteAllText(composePath, """
        services:
          prometheus:
            image: prom/prometheus
            ports:
              - "9090:9090"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP004");
    }

    [Fact]
    public async Task AnalyzeAsync_StillReportsDockerSocketInDevelopmentComposeFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var composePath = Path.Combine(fixture.Path, "devenv", "docker", "compose.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(composePath)!);
        File.WriteAllText(composePath, """
        services:
          builder:
            image: docker
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP006");
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
    public async Task AnalyzeAsync_InterpolatedSecretEnvironment_NoCOMP005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            environment:
              PASSWORD: ${PASSWORD}
              TOKEN: $TOKEN
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP005");
    }

    [Fact]
    public async Task AnalyzeAsync_NoComposeFile_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_SecureCompose_NoSecurityFindings()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx:1.25
            ports:
              - "127.0.0.1:8080:80"
            volumes:
              - appdata:/data
        volumes:
          appdata:
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP001");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP002");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP004");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP005");
    }

    // ── COMP006: Docker socket mount ──────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsDockerSocketMount()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - "/var/run/docker.sock:/var/run/docker.sock"
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP006" && f.IsBlocking);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsLongSyntaxDockerSocketMount()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - type: bind
                source: /var/run/docker.sock
                target: /var/run/docker.sock
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP006" && f.IsBlocking);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP003");
    }

    [Fact]
    public async Task AnalyzeAsync_LongSyntaxReadOnlyBindMountIsLowSeverity()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - type: bind
                source: /var/log/app
                target: /logs
                read_only: true
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-COMP003");
        Assert.Equal(Severity.Low, finding.Severity);
    }

    [Fact]
    public async Task AnalyzeAsync_OrdinaryNamedVolume_NoCOMP006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            volumes:
              - app-data:/data
        volumes:
          app-data:
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP006");
    }

    // ── COMP007: .env file loading ────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsEnvProduction()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            env_file: .env.production
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-COMP007");
    }

    [Fact]
    public async Task AnalyzeAsync_EnvFileExample_NoCOMP007()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            env_file: .env.example
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP007");
    }

    [Fact]
    public async Task AnalyzeAsync_EnvFileListAndQuotedScalar_DetectsRiskyEntries()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            env_file:
              - ".env.production"
              - path: ./runtime.secret
          worker:
            image: nginx
            env_file: '.env.local'
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Equal(3, result.Findings.Count(f => f.RuleId == "TRUST-COMP007"));
    }

    [Fact]
    public async Task AnalyzeAsync_EnvFileListExample_NoCOMP007()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "docker-compose.yml"), """
        services:
          app:
            image: nginx
            env_file:
              - .env.example
              - sample.secret
        """);

        var analyzer = new DockerComposeAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-COMP007");
    }
}

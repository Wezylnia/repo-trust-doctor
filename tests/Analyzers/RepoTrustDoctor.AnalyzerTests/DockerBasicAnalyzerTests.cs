using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DockerBasicAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReportsSecretEnvWithRedactedValue()
    {
        using var fixture = TemporaryRepository.Create();
        // We write a .dockerignore to avoid triggering TRUST-DOCKER001, so we only get our expected finding.
        File.WriteAllText(Path.Combine(fixture.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fixture.Path, "Dockerfile"), """
        FROM alpine:3.18
        ENV PASSWORD=supersecretpassword
        USER appuser
        HEALTHCHECK NONE
        """);

        var analyzer = new DockerBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-DOCKER005");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(2, evidence.LineNumber);
        Assert.Equal("ENV PASSWORD=[redacted]", evidence.Value);
    }
}

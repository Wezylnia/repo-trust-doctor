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

    [Fact]
    public async Task AnalyzeAsync_ReportsMissingMultiStageBuild_WhenSingleStage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fixture.Path, "Dockerfile"), """
        FROM alpine:3.18
        USER appuser
        HEALTHCHECK NONE
        """);

        var analyzer = new DockerBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-DOCKER006");
        Assert.Equal("TRUST-DOCKER006", finding.RuleId);
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.Medium, finding.Confidence);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportMissingMultiStageBuild_WhenMultiStage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fixture.Path, "Dockerfile"), """
        FROM golang:1.21 AS builder
        WORKDIR /app
        COPY . .
        RUN go build -o main .

        FROM alpine:3.18
        COPY --from=builder /app/main /main
        USER appuser
        HEALTHCHECK NONE
        """);

        var analyzer = new DockerBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DOCKER006");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotCountCommentedFrom()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(fixture.Path, "Dockerfile"), """
        # FROM scratch
        FROM alpine:3.18
        #  FROM ubuntu
        USER appuser
        HEALTHCHECK NONE
        """);

        var analyzer = new DockerBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        // Should report TRUST-DOCKER006 because only one active FROM is counted (alpine)
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DOCKER006");
    }
}


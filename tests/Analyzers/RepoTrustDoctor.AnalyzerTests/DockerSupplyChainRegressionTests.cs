using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DockerSupplyChainRegressionTests
{
    private static readonly DockerBasicAnalyzer Analyzer = new();

    [Fact]
    public async Task DOCKER013_FromOptionAfterOtherCopyOption_Reports()
    {
        using var repository = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(repository.Path, ".dockerignore"), "*.log");
        File.WriteAllText(Path.Combine(repository.Path, "Dockerfile"), """
        FROM alpine:3.20
        COPY --chown=app --from=nginx:latest /usr/share/nginx/html /app
        USER app
        """);

        var result = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var finding = Assert.Single(result.Findings.Where(finding => finding.RuleId == "TRUST-DOCKER013"));
        Assert.Contains("nginx:latest", finding.IdentityKey, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SupplyChainIdentityKeys_RemainStableWhenLinesAreInsertedAboveFindings()
    {
        using var repository = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(repository.Path, ".dockerignore"), "*.log");
        var dockerfilePath = Path.Combine(repository.Path, "Dockerfile");

        const string original = """
        FROM alpine:3.20
        ARG API_TOKEN
        RUN apt-get update && apt-get install -y curl
        COPY --from=nginx:latest /usr/share/nginx/html /app
        USER app
        """;

        File.WriteAllText(dockerfilePath, original);
        var first = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        File.WriteAllText(dockerfilePath, """
        # unrelated comment

        # another unrelated comment
        """ + Environment.NewLine + original);
        var second = await Analyzer.AnalyzeAsync(
            new AnalysisContext(repository.Path, repository.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        foreach (var ruleId in new[] { "TRUST-DOCKER013", "TRUST-DOCKER015", "TRUST-DOCKER016" })
        {
            var firstFinding = Assert.Single(first.Findings.Where(finding => finding.RuleId == ruleId));
            var secondFinding = Assert.Single(second.Findings.Where(finding => finding.RuleId == ruleId));
            Assert.Equal(firstFinding.IdentityKey, secondFinding.IdentityKey);
            Assert.Equal(firstFinding.Fingerprints, secondFinding.Fingerprints);
        }
    }
}

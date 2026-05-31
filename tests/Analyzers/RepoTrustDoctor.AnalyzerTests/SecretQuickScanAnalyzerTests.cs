using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class SecretQuickScanAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_RedactsSecretEvidenceAndReportsLineNumber()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        safe=true
        token={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET003");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(2, evidence.LineNumber);
        Assert.Equal("[redacted]", evidence.Value);
    }
}

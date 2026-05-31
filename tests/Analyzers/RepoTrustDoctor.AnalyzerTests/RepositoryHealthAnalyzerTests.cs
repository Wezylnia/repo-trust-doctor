using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class RepositoryHealthAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReportsMissingLicense()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO002");
    }
}

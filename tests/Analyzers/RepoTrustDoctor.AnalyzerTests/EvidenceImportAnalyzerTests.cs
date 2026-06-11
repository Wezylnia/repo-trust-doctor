using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class EvidenceImportAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_SbomAndProvenanceAreInformationalEvidence()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "attestation.json"), "{}");

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-EVI001" && finding.Severity == Severity.Info);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-EVI003" && finding.Severity == Severity.Info);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-EVI002");
    }
}

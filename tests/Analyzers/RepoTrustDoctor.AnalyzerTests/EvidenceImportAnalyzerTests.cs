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

    // ── EVI004: unparseable SBOM ──────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_InvalidSbomJson_ReportsEVI004()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), "{invalid json!!}");

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI004");
    }

    [Fact]
    public async Task AnalyzeAsync_ValidSbomJson_NoEVI004()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"x"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI004");
    }

    // ── EVI005: empty SBOM ───────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_EmptyComponentsArray_ReportsEVI005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"bomFormat":"CycloneDX","components":[]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI005");
    }

    [Fact]
    public async Task AnalyzeAsync_NonEmptyComponents_NoEVI005()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"x"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI005");
    }

    // ── EVI006: unparseable provenance ────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_InvalidProvenanceJson_ReportsEVI006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "provenance.json"), "not json!!");

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI006");
    }

    [Fact]
    public async Task AnalyzeAsync_InvalidIntotoLine_ReportsEVI006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "build.intoto.jsonl"), """
        {"valid":"line"}
        not-valid-json
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI006");
    }

    [Fact]
    public async Task AnalyzeAsync_ValidIntotoJsonl_NoEVI006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "build.intoto.jsonl"), """
        {"payload":"data"}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI006");
    }
}

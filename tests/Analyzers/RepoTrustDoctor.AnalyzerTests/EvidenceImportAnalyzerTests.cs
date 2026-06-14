using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
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

    [Fact]
    public async Task AnalyzeAsync_NonArrayComponents_DoesNotThrow()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":{"name":"x"}}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI001");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI004");
    }

    [Fact]
    public async Task AnalyzeAsync_NonPackageUrlPurl_ReportsEVI008()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"x","purl":"npm/x@1.0.0"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI008");
    }

    [Fact]
    public async Task AnalyzeAsync_ValidScopedPackageUrl_NoEVI008()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"@scope/name","purl":"pkg:npm/%40scope/name@1.0.0"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI008");
    }

    [Fact]
    public async Task AnalyzeAsync_SmallSbomWithoutDependencyInventory_NoEVI007()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"x"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI007");
    }

    [Fact]
    public async Task AnalyzeAsync_SbomSmallerThanInventory_ReportsEVI007()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"components":[{"name":"x"},{"name":"y"}]}
        """);

        var context = new AnalysisContext("https://github.com/acme/service", fixture.Path, AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, new DependencyInventoryArtifact(
            [],
            [],
            Enumerable.Range(0, 20)
                .Select(i => new DependencyPackageInfo(DependencyEcosystem.Npm, $"pkg-{i}", "1.0.0", DependencyScope.Production, "package.json", null, true, true, false))
                .ToArray(),
            [],
            new Dictionary<string, string>())));

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-EVI007");
    }

    [Fact]
    public async Task AnalyzeAsync_MetadataTargetMatchingGitHubTarget_NoEVI009()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sbom.json"), """
        {"metadata":{"component":{"name":"acme/service"}},"components":[{"name":"x"}]}
        """);

        var analyzer = new EvidenceImportAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext("git@github.com:acme/service.git", fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-EVI009");
    }

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

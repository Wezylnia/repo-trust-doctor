using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class ReleaseEvidenceAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ChangelogMismatchReportsPackageVersionRules()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v2.0.0 - 2026-06-10
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        { "name": "example", "version": "1.0.0" }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_ArtifactWithoutIntegrityEvidenceReportsRules()
    {
        using var fixture = TemporaryRepository.Create();
        var dist = Directory.CreateDirectory(Path.Combine(fixture.Path, "dist"));
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip"), "synthetic");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_GitignoredRootArtifactDirectoryDoesNotReportArtifactRules()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitignore"), "artifacts/\n");
        var publish = Directory.CreateDirectory(Path.Combine(fixture.Path, "artifacts", "publish"));
        File.WriteAllText(Path.Combine(publish.FullName, "tool.zip"), "synthetic");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_ArtifactWithChecksumAndSbomDoesNotReportArtifactRules()
    {
        using var fixture = TemporaryRepository.Create();
        var dist = Directory.CreateDirectory(Path.Combine(fixture.Path, "dist"));
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip"), "synthetic");
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip.sha256"), "abc");
        File.WriteAllText(Path.Combine(dist.FullName, "sbom.cdx.json"), "{}");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_ReleaseWorkflowWithoutIntegrityStepsReportsRule()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDir = Directory.CreateDirectory(Path.Combine(fixture.Path, ".github", "workflows"));
        File.WriteAllText(Path.Combine(workflowDir.FullName, "release.yml"), """
        name: release
        on:
          push:
            tags: ["v*"]
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REL005");
        Assert.Equal(Severity.Medium, finding.Severity);
    }
}

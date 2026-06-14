using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class WorkspaceAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsNpmWorkspaces()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
            "name": "root",
            "workspaces": ["packages/*"]
        }
        """);

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-WS001");
        Assert.Equal(Severity.Info, finding.Severity);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == WorkspaceArtifact.ArtifactKey);
        var ws = Assert.IsType<WorkspaceArtifact>(artifact.Value);
        Assert.Contains(ws.Members, m => m.Ecosystem == "npm" && m.MemberPath == "packages/*");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportNpmWorkspace_WhenNoWorkspaces()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """{"name": "myapp"}""");

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-WS001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsCargoWorkspace()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/app", "crates/lib"]
        """);

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-WS002");
        Assert.Equal(Severity.Info, finding.Severity);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == WorkspaceArtifact.ArtifactKey);
        var ws = Assert.IsType<WorkspaceArtifact>(artifact.Value);
        Assert.Contains(ws.Members, m => m.Ecosystem == "cargo" && m.MemberPath == "crates/app");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsGoWorkspace()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.work"), """
        go 1.22

        use (
            ./module1
            ./module2/...
        )
        """);

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-WS003");
        Assert.Equal(Severity.Info, finding.Severity);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == WorkspaceArtifact.ArtifactKey);
        var ws = Assert.IsType<WorkspaceArtifact>(artifact.Value);
        Assert.Contains(ws.Members, m => m.Ecosystem == "go");
    }

    [Fact]
    public async Task AnalyzeAsync_EmptyRepository_NoFindings()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NonObjectPackageJson_IsIgnored()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), "\"Package moved elsewhere\"");

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        Assert.Empty(result.Findings);
    }
}

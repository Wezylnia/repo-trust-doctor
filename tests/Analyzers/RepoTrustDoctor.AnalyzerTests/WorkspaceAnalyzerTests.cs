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
        Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app"));
        File.WriteAllText(Path.Combine(fixture.Path, "packages", "app", "package.json"), """{"name":"app"}""");
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
        Assert.Contains(ws.Members, m => m.Ecosystem == "npm" && m.MemberPath == "packages/app");
        Assert.DoesNotContain(ws.Members, m => m.MemberPath.Contains('*', StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsYarnObjectWorkspaces_AndDeduplicatesOverlappingPatterns()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app"));
        Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "ignored"));
        File.WriteAllText(Path.Combine(fixture.Path, "packages", "app", "package.json"), """{"name":"app"}""");
        File.WriteAllText(Path.Combine(fixture.Path, "packages", "ignored", "package.json"), """{"name":"ignored"}""");
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
            "name": "root",
            "workspaces": {
                "packages": ["packages/*", "packages/app", "!packages/ignored"],
                "nohoist": ["**/native-module"]
            }
        }
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var workspace = Assert.IsType<WorkspaceArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == WorkspaceArtifact.ArtifactKey).Value);
        var member = Assert.Single(workspace.Members);
        Assert.Equal("packages/app", member.MemberPath);
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
        Directory.CreateDirectory(Path.Combine(fixture.Path, "crates", "app"));
        Directory.CreateDirectory(Path.Combine(fixture.Path, "crates", "lib"));
        File.WriteAllText(Path.Combine(fixture.Path, "crates", "app", "Cargo.toml"), "[package]\nname = \"app\"");
        File.WriteAllText(Path.Combine(fixture.Path, "crates", "lib", "Cargo.toml"), "[package]\nname = \"lib\"");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]
        members = ["crates/*"]
        """);

        var analyzer = new WorkspaceAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-WS002");
        Assert.Equal(Severity.Info, finding.Severity);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == WorkspaceArtifact.ArtifactKey);
        var ws = Assert.IsType<WorkspaceArtifact>(artifact.Value);
        Assert.Contains(ws.Members, m => m.Ecosystem == "cargo" && m.MemberPath == "crates/app");
        Assert.Contains(ws.Members, m => m.Ecosystem == "cargo" && m.MemberPath == "crates/lib");
    }

    [Fact]
    public async Task AnalyzeAsync_CargoWorkspace_ExpandsMembersAndAppliesExclude()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "crates", "app"));
        Directory.CreateDirectory(Path.Combine(fixture.Path, "crates", "fixture"));
        File.WriteAllText(Path.Combine(fixture.Path, "crates", "app", "Cargo.toml"), "[package]\nname = \"app\"");
        File.WriteAllText(Path.Combine(fixture.Path, "crates", "fixture", "Cargo.toml"), "[package]\nname = \"fixture\"");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace] # root declaration
        members = [
          "crates/*",
        ]
        exclude = ["crates/fixture"]
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var workspace = Assert.IsType<WorkspaceArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == WorkspaceArtifact.ArtifactKey).Value);
        var member = Assert.Single(workspace.Members);
        Assert.Equal("crates/app", member.MemberPath);
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsGoWorkspace()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "module1"));
        Directory.CreateDirectory(Path.Combine(fixture.Path, "module2"));
        File.WriteAllText(Path.Combine(fixture.Path, "module1", "go.mod"), "module example.com/module1");
        File.WriteAllText(Path.Combine(fixture.Path, "module2", "go.mod"), "module example.com/module2");
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
        Assert.Contains(ws.Members, m => m.Ecosystem == "go" && m.MemberPath == "module1");
        Assert.Contains(ws.Members, m => m.Ecosystem == "go" && m.MemberPath == "module2");
    }

    [Fact]
    public async Task AnalyzeAsync_GoWorkspace_ParsesSingleLineUseRelativeToWorkspaceFile()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "tools"));
        Directory.CreateDirectory(Path.Combine(fixture.Path, "shared"));
        File.WriteAllText(Path.Combine(fixture.Path, "shared", "go.mod"), "module example.com/shared");
        File.WriteAllText(Path.Combine(fixture.Path, "tools", "go.work"), """
        go 1.22
        use ../shared // shared module
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var workspace = Assert.IsType<WorkspaceArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == WorkspaceArtifact.ArtifactKey).Value);
        var member = Assert.Single(workspace.Members);
        Assert.Equal("go", member.Ecosystem);
        Assert.Equal("shared", member.MemberPath);
        Assert.Equal("tools", member.RootDirectory);
    }

    [Fact]
    public async Task AnalyzeAsync_GoWorkspace_ResolvesRootModule()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), "module example.com/root");
        File.WriteAllText(Path.Combine(fixture.Path, "go.work"), """
        go 1.22
        use .
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var workspace = Assert.IsType<WorkspaceArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == WorkspaceArtifact.ArtifactKey).Value);
        Assert.Equal(".", Assert.Single(workspace.Members).MemberPath);
    }

    [Fact]
    public async Task AnalyzeAsync_EmptyCargoWorkspace_IsStillDetected()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [workspace]

        [workspace.package]
        edition = "2024"
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-WS002");
        Assert.Empty(result.Artifacts ?? []);
    }

    [Fact]
    public async Task AnalyzeAsync_WorkspaceDeclarationWithoutManifest_DoesNotCreatePhantomMember()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
            "name": "root",
            "workspaces": ["packages/*"]
        }
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-WS001");
        Assert.Empty(result.Artifacts ?? []);
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

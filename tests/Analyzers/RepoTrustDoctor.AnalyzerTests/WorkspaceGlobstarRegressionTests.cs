using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class WorkspaceGlobstarRegressionTests
{
    [Fact]
    public async Task AnalyzeAsync_GlobstarPrefixMatchesNestedWorkspaceMember()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app"));
        File.WriteAllText(Path.Combine(fixture.Path, "packages", "app", "package.json"), """{"name":"nested-app"}""");
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "name": "root",
          "workspaces": ["**/app"]
        }
        """);

        var result = await new WorkspaceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var workspace = Assert.IsType<WorkspaceArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == WorkspaceArtifact.ArtifactKey).Value);
        Assert.Contains(workspace.Members, member => member.MemberPath == "packages/app");
    }
}

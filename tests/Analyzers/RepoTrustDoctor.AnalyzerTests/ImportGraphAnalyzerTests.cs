using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class ImportGraphAnalyzerTests
{
    [Fact]
    public async Task ImportGraphAnalyzer_BuildsGraphAndDetectsCentralFiles()
    {
        using var fixture = TemporaryRepository.Create();

        // Let's create a highly central file: src/Common.ts (JS/TS relative import paths)
        File.WriteAllText(Path.Combine(fixture.Path, "Common.ts"), "export class Common {}");

        // And 10 files that import/use it
        for (int i = 1; i <= 10; i++)
        {
            File.WriteAllText(
                Path.Combine(fixture.Path, $"Service{i}.ts"),
                "import { Common } from './Common';"
            );
        }

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        
        // Also provide a coverage artifact with low coverage for Common to trigger TRUST-CODE011
        var coverageArtifact = new CoverageArtifact(
            [new CoverageReportInfo("coverage.xml", CoverageReportFormat.Cobertura, 0.4, 0.2, 4, 10, 1, 5)],
            [new CoverageFileInfo("Common", 0.4, 0.2, 4, 10, 1, 5)],
            new Dictionary<string, string>()
        );
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, coverageArtifact));

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        // Verify findings
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE010"); // central file
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE011"); // low coverage

        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);

        Assert.Contains("Common", graph.CentralFiles.Select(f => f.FilePath));
        Assert.True(graph.Edges.Count > 0);
    }
}

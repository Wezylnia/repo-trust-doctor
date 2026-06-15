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
            [new CoverageFileInfo("Common.ts", 0.4, 0.2, 4, 10, 1, 5)],
            new Dictionary<string, string>()
        );
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, coverageArtifact));

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        // Verify findings
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE010"); // central file
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE011"); // low coverage

        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);

        Assert.Contains("Common.ts", graph.CentralFiles.Select(f => f.FilePath));
        Assert.True(graph.Edges.Count > 0);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_IgnoresExternalPackageImports()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "App.tsx"), """
        import React from 'react';
        import { render } from '@testing-library/react';
        export function App() { return null; }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);
        Assert.Empty(graph.Edges);
        Assert.Empty(graph.CentralFiles);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_IgnoresTypeOnlyTypeScriptImports()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Report.ts"), """
        export interface RepositoryScan {
            target: string;
        }
        """);

        for (var index = 1; index <= 12; index++)
        {
            File.WriteAllText(
                Path.Combine(fixture.Path, $"View{index}.tsx"),
                "import type { RepositoryScan } from './Report';");
        }

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE010");
        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);
        Assert.Empty(graph.Edges);
        Assert.Empty(graph.CentralFiles);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_SkipsTestFixtureAndDocumentationSources()
    {
        using var fixture = TemporaryRepository.Create();
        var testDirectory = Path.Combine(fixture.Path, "tests");
        Directory.CreateDirectory(testDirectory);
        File.WriteAllText(Path.Combine(testDirectory, "Common.ts"), "export class Common {}");

        for (var index = 1; index <= 12; index++)
        {
            File.WriteAllText(
                Path.Combine(testDirectory, $"Fixture{index}.ts"),
                "import { Common } from './Common';");
        }

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE010");
        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);
        Assert.Empty(graph.Edges);
        Assert.Empty(graph.CentralFiles);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_DoesNotReportMissingCoverageWhenNoCoverageReportWasImported()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Common.ts"), "export class Common {}");
        for (int i = 1; i <= 10; i++)
        {
            File.WriteAllText(
                Path.Combine(fixture.Path, $"Service{i}.ts"),
                "import { Common } from './Common';");
        }

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, new CoverageArtifact([], [], new Dictionary<string, string>())));

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE010");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE011");
    }

    [Fact]
    public async Task ImportGraphAnalyzer_MatchesCoverageByUnambiguousFileSuffix()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "shared");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "Common.ts"), "export class Common {}");

        for (int i = 1; i <= 10; i++)
        {
            File.WriteAllText(
                Path.Combine(fixture.Path, "src", $"Service{i}.ts"),
                "import { Common } from './shared/Common';");
        }

        var coverageArtifact = new CoverageArtifact(
            [new CoverageReportInfo("coverage.xml", CoverageReportFormat.Cobertura, 0.4, 0.2, 4, 10, 1, 5)],
            [new CoverageFileInfo("shared/Common.ts", 0.4, 0.2, 4, 10, 1, 5)],
            new Dictionary<string, string>());
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, coverageArtifact));

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE011");
        var artifact = Assert.Single(result.Artifacts!, art => art.Key == ImportGraphArtifact.ArtifactKey);
        var graph = Assert.IsType<ImportGraphArtifact>(artifact.Value);
        Assert.Contains("src/shared/Common.ts", graph.CentralFiles.Select(f => f.FilePath));
    }

    [Fact]
    public async Task ImportGraphAnalyzer_GoStringLiteralDoesNotCreateImportEdge()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), "module example.com/repo // local module");
        Directory.CreateDirectory(Path.Combine(fixture.Path, "internal", "service"));
        File.WriteAllText(
            Path.Combine(fixture.Path, "internal", "service", "service.go"),
            "package service");
        File.WriteAllText(
            Path.Combine(fixture.Path, "main.go"),
            """
            package main

            func main() {
                message := "example.com/repo/internal/service"
                _ = message
            }
            """);

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var graph = Assert.IsType<ImportGraphArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == ImportGraphArtifact.ArtifactKey).Value);
        Assert.Empty(graph.Edges);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_GoImportStatementsResolveUniqueLocalPackage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), "module example.com/repo // local module");
        Directory.CreateDirectory(Path.Combine(fixture.Path, "internal", "service"));
        File.WriteAllText(
            Path.Combine(fixture.Path, "internal", "service", "service.go"),
            "package service");
        File.WriteAllText(
            Path.Combine(fixture.Path, "main.go"),
            """
            package main

            import (
                svc "example.com/repo/internal/service"
                "net/http"
            )
            """);

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var graph = Assert.IsType<ImportGraphArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == ImportGraphArtifact.ArtifactKey).Value);
        Assert.Equal(
            ["internal/service/service.go"],
            Assert.Single(graph.Edges).Value);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_GoImportDoesNotChooseArbitraryFileFromMultiFilePackage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), "module example.com/repo");
        Directory.CreateDirectory(Path.Combine(fixture.Path, "internal", "service"));
        File.WriteAllText(
            Path.Combine(fixture.Path, "internal", "service", "service.go"),
            "package service");
        File.WriteAllText(
            Path.Combine(fixture.Path, "internal", "service", "handler.go"),
            "package service");
        File.WriteAllText(
            Path.Combine(fixture.Path, "main.go"),
            """
            package main
            import "example.com/repo/internal/service"
            """);

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var graph = Assert.IsType<ImportGraphArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == ImportGraphArtifact.ArtifactKey).Value);
        Assert.Empty(graph.Edges);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_CSharpNamespaceUsingDoesNotCreateFileEdge()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "Company", "Project"));
        File.WriteAllText(
            Path.Combine(fixture.Path, "Company", "Project", "Services.cs"),
            "namespace Company.Project.Services;");
        File.WriteAllText(
            Path.Combine(fixture.Path, "App.cs"),
            "using Company.Project.Services;");

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var graph = Assert.IsType<ImportGraphArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == ImportGraphArtifact.ArtifactKey).Value);
        Assert.Empty(graph.Edges);
        Assert.Equal("0", graph.Metrics["import.graph.file.count"]);
    }

    [Fact]
    public async Task ImportGraphAnalyzer_DeduplicatesRepeatedSourceTargetEdges()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Common.ts"), "export class Common {}");
        File.WriteAllText(
            Path.Combine(fixture.Path, "App.ts"),
            """
            import { Common } from './Common';
            import { Common as CommonAlias } from './Common';
            export { Common, CommonAlias };
            """);

        var result = await new ImportGraphAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var graph = Assert.IsType<ImportGraphArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == ImportGraphArtifact.ArtifactKey).Value);
        Assert.Equal(["Common.ts"], graph.Edges["App.ts"]);
        Assert.Equal("1", graph.Metrics["import.graph.edge.count"]);
        Assert.Empty(graph.CentralFiles);
    }
}

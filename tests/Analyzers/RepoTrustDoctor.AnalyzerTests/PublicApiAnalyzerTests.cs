using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class PublicApiAnalyzerTests
{
    [Fact]
    public void ExtractSymbols_ReturnsPublicTypesMethodsAndProperties()
    {
        var symbols = PublicApiAnalyzer.ExtractSymbols("""
        namespace Demo;
        public sealed class WidgetClient
        {
            public string Name { get; init; }
            public async Task<Widget> GetAsync(string id) => throw new NotImplementedException();
            internal void Hidden() { }
        }
        """);

        Assert.Contains("type WidgetClient", symbols);
        Assert.Contains("member WidgetClient.Name", symbols);
        Assert.Contains("member WidgetClient.GetAsync()", symbols);
        Assert.DoesNotContain("member WidgetClient.Hidden()", symbols);
    }

    [Fact]
    public async Task PublicApiAnalyzer_ReportsMissingBaselineWhenApiExists()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "WidgetClient.cs"), """
        public sealed class WidgetClient
        {
            public string Name { get; init; }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE008");
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Null(artifact.BaselinePath);
        Assert.Equal(2, artifact.Symbols.Count);
    }

    [Fact]
    public async Task PublicApiAnalyzer_ReportsAddedAndRemovedSymbols()
    {
        using var fixture = TemporaryRepository.Create();
        var baselineDirectory = Path.Combine(fixture.Path, ".repo-trust");
        Directory.CreateDirectory(baselineDirectory);
        File.WriteAllText(Path.Combine(baselineDirectory, "public-api-baseline.txt"), """
        type WidgetClient
        member WidgetClient.Name
        member WidgetClient.Delete()
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "WidgetClient.cs"), """
        public sealed class WidgetClient
        {
            public string Name { get; init; }
            public void Create() { }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings);
        Assert.Equal("TRUST-CODE009", finding.RuleId);
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Contains("member WidgetClient.Create()", artifact.AddedSymbols);
        Assert.Contains("member WidgetClient.Delete()", artifact.RemovedSymbols);
        Assert.Equal("True", artifact.Metrics["code.public_api.diff.comparable"]);
    }

    [Fact]
    public async Task PublicApiAnalyzer_SkipsWhenBaselineMatches()
    {
        using var fixture = TemporaryRepository.Create();
        var docsDirectory = Path.Combine(fixture.Path, "docs");
        Directory.CreateDirectory(docsDirectory);
        File.WriteAllText(Path.Combine(docsDirectory, "public-api-baseline.txt"), """
        type WidgetClient
        member WidgetClient.Name
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "WidgetClient.cs"), """
        public sealed class WidgetClient
        {
            public string Name { get; init; }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Equal("docs/public-api-baseline.txt", artifact.BaselinePath);
    }

    [Fact]
    public async Task PublicApiAnalyzer_SkipsTestSources()
    {
        using var fixture = TemporaryRepository.Create();
        var testsDirectory = Path.Combine(fixture.Path, "tests");
        Directory.CreateDirectory(testsDirectory);
        File.WriteAllText(Path.Combine(testsDirectory, "WidgetClientTests.cs"), """
        public sealed class WidgetClientTests
        {
            public void CreatesWidget() { }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Symbols);
    }

    [Fact]
    public async Task PublicApiAnalyzer_SupportsMultiLanguageExtraction()
    {
        using var fixture = TemporaryRepository.Create();
        
        // TypeScript
        File.WriteAllText(Path.Combine(fixture.Path, "index.ts"), """
        export class User {
            id: string;
        }
        export function getUser(): User { return null; }
        """);

        // Python
        File.WriteAllText(Path.Combine(fixture.Path, "main.py"), """
        class Account:
            pass
        def transfer():
            pass
        """);

        // Go
        File.WriteAllText(Path.Combine(fixture.Path, "main.go"), """
        package main
        func RunProcess() {}
        type DataModel struct {}
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        
        Assert.Contains("export class User", artifact.Symbols);
        Assert.Contains("export function getUser", artifact.Symbols);
        Assert.Contains("class Account", artifact.Symbols);
        Assert.Contains("def transfer", artifact.Symbols);
        Assert.Contains("func main.RunProcess", artifact.Symbols);
        Assert.Contains("type main.DataModel", artifact.Symbols);
    }

    [Fact]
    public async Task PublicApiAnalyzer_SkipsBaselineDiffWhenSourceInventoryIsIncomplete()
    {
        using var fixture = TemporaryRepository.Create();
        var baselineDirectory = Path.Combine(fixture.Path, ".repo-trust");
        Directory.CreateDirectory(baselineDirectory);
        File.WriteAllText(Path.Combine(baselineDirectory, "public-api-baseline.txt"), """
        type PreviousClient
        member PreviousClient.Send()
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "CurrentClient.cs"), """
        public sealed class CurrentClient
        {
            public void Send() { }
        }
        """);
        File.WriteAllText(
            Path.Combine(fixture.Path, "OversizedClient.cs"),
            new string(' ', (int)RepositoryFileSystem.DefaultMaxReadableFileBytes + 1));
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE009");
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.AddedSymbols);
        Assert.Empty(artifact.RemovedSymbols);
        Assert.Equal("1", artifact.Metrics["code.public_api.unreadable_file.count"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.inventory.complete"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.diff.comparable"]);
        Assert.Contains(result.Warnings!, warning => warning.Contains("inventory is incomplete", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PublicApiAnalyzer_SkipsBaselineDiffWhenSourceSelectionIsTruncated()
    {
        using var fixture = TemporaryRepository.Create();
        var baselineDirectory = Path.Combine(fixture.Path, ".repo-trust");
        Directory.CreateDirectory(baselineDirectory);
        File.WriteAllText(Path.Combine(baselineDirectory, "public-api-baseline.txt"), """
        type FirstClient
        type SecondClient
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "FirstClient.cs"), "public sealed class FirstClient { }");
        File.WriteAllText(Path.Combine(fixture.Path, "SecondClient.cs"), "public sealed class SecondClient { }");
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer(maxAnalyzedSourceFiles: 1)
            .AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE009");
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.AddedSymbols);
        Assert.Empty(artifact.RemovedSymbols);
        Assert.Equal("True", artifact.Metrics["code.public_api.truncated"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.inventory.complete"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.diff.comparable"]);
        Assert.Contains(result.Warnings!, warning =>
            warning.Contains("processed 1 of 2 source files", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PublicApiAnalyzer_SkipsOversizedBaselineWithoutReportingItMissing()
    {
        using var fixture = TemporaryRepository.Create();
        var baselineDirectory = Path.Combine(fixture.Path, ".repo-trust");
        Directory.CreateDirectory(baselineDirectory);
        File.WriteAllText(
            Path.Combine(baselineDirectory, "public-api-baseline.txt"),
            new string('x', (4 * 1024 * 1024) + 1));
        File.WriteAllText(Path.Combine(fixture.Path, "WidgetClient.cs"), """
        public sealed class WidgetClient
        {
            public void Send() { }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new PublicApiAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding =>
            finding.RuleId is "TRUST-CODE008" or "TRUST-CODE009");
        var artifact = Assert.IsType<CodePublicApiArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Equal(".repo-trust/public-api-baseline.txt", artifact.BaselinePath);
        Assert.Equal("True", artifact.Metrics["code.public_api.baseline.present"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.baseline.readable"]);
        Assert.Equal("False", artifact.Metrics["code.public_api.diff.comparable"]);
        Assert.Contains(result.Warnings!, warning => warning.Contains("4 MiB safety limit", StringComparison.Ordinal));
    }
}

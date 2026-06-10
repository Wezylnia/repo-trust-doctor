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
}

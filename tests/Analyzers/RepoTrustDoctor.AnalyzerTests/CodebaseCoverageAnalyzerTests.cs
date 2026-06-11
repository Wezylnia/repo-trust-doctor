using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CodebaseCoverageAnalyzerTests
{
    [Fact]
    public async Task CoverageImportAnalyzer_ParsesCoberturaCoverageReport()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "coverage.xml"), """
        <?xml version="1.0" encoding="utf-8"?>
        <coverage line-rate="0.75" branch-rate="0.5" lines-covered="3" lines-valid="4" branches-covered="1" branches-valid="2">
          <packages>
            <package name="RepoTrustDoctor">
              <classes>
                <class name="ImportantService" filename="src/ImportantService.cs" line-rate="0.75" branch-rate="0.5" />
              </classes>
            </package>
          </packages>
        </coverage>
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CoverageImportAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE001");
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == CoverageArtifact.ArtifactKey);
        var coverage = Assert.IsType<CoverageArtifact>(artifact.Value);
        var report = Assert.Single(coverage.Reports);
        Assert.Equal(CoverageReportFormat.Cobertura, report.Format);
        Assert.Equal(0.75, report.LineRate);
        Assert.Equal("src/ImportantService.cs", Assert.Single(coverage.Files).FilePath);
    }

    [Fact]
    public async Task CoverageImportAnalyzer_ParsesLcovCoverageReport()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "lcov.info"), """
        TN:
        SF:src/payment/PaymentService.cs
        DA:10,1
        DA:11,0
        DA:12,3
        BRDA:10,0,0,1
        BRDA:10,0,1,0
        end_of_record
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CoverageImportAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var coverage = Assert.IsType<CoverageArtifact>(Assert.Single(result.Artifacts!).Value);
        var report = Assert.Single(coverage.Reports);
        Assert.Equal(CoverageReportFormat.Lcov, report.Format);
        Assert.Equal(2.0 / 3.0, report.LineRate);
        var file = Assert.Single(coverage.Files);
        Assert.Equal(2, file.CoveredLines);
        Assert.Equal(3, file.TotalLines);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE002");
    }

    [Fact]
    public async Task CoverageImportAnalyzer_ReportsMissingCoverageWithoutExecutingTests()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Program.cs"), "Console.WriteLine(\"hello\");");
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CoverageImportAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE001");
        var coverage = Assert.IsType<CoverageArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(coverage.Reports);
        Assert.Empty(coverage.Files);
    }

    [Fact]
    public async Task CoverageImportAnalyzer_RejectsUnsafeOrMalformedXml()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "coverage.xml"), """
        <!DOCTYPE coverage [
          <!ENTITY ext SYSTEM "file:///C:/Windows/win.ini">
        ]>
        <coverage line-rate="&ext;" />
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CoverageImportAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE003");
        Assert.NotEmpty(result.Warnings!);
    }

    [Fact]
    public async Task CoverageImportAnalyzer_MergesAndNormalizesPathsForMonorepo()
    {
        using var fixture = TemporaryRepository.Create();
        
        // Report 1: Cobertura
        File.WriteAllText(Path.Combine(fixture.Path, "cobertura.xml"), $"""
        <?xml version="1.0" encoding="utf-8"?>
        <coverage line-rate="0.8" lines-covered="8" lines-valid="10">
          <packages>
            <package name="Core">
              <classes>
                <class name="Common" filename="{fixture.Path.Replace('\\', '/')}/src/core/Common.cs" line-rate="0.8" />
              </classes>
            </package>
          </packages>
        </coverage>
        """);

        // Report 2: Lcov
        File.WriteAllText(Path.Combine(fixture.Path, "lcov.info"), """
        SF:src/core/Common.cs
        DA:10,1
        DA:11,1
        end_of_record
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new CoverageImportAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var coverage = Assert.IsType<CoverageArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Equal(2, coverage.Reports.Count);
        
        var file = Assert.Single(coverage.Files);
        Assert.Equal("src/core/Common.cs", file.FilePath);
    }
}

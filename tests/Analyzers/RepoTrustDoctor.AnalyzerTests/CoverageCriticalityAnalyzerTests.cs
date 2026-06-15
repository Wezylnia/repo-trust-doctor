using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CoverageCriticalityAnalyzerTests
{
    [Fact]
    public async Task CoverageCriticalityAnalyzer_ReportsLowCoverageOnCriticalFile()
    {
        var context = CreateContext(
            [new CoverageFileInfo("src/auth/AuthService.cs", 0.25, null, 1, 4, null, null)],
            [new CodeCriticalityFile("src/auth/AuthService.cs", 75, 80, [CodeCriticalityReason.Authentication, CodeCriticalityReason.Secrets], 3)]);

        var result = await new CoverageCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings);
        Assert.Equal("TRUST-CODE007", finding.RuleId);
        Assert.True(finding.IsBlocking);
    }

    [Fact]
    public async Task CoverageCriticalityAnalyzer_ReportsMissingCoverageWhenReportExists()
    {
        var context = CreateContext(
            [new CoverageFileInfo("src/other/Other.cs", 1.0, null, 10, 10, null, null)],
            [new CodeCriticalityFile("src/payments/PaymentService.cs", 75, 70, [CodeCriticalityReason.Payments], 4)]);

        var result = await new CoverageCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.Message.Contains("missing", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CoverageCriticalityAnalyzer_SkipsCriticalFileWithAdequateCoverage()
    {
        var context = CreateContext(
            [new CoverageFileInfo("src/security/CryptoService.cs", 0.95, null, 19, 20, null, null)],
            [new CodeCriticalityFile("src/security/CryptoService.cs", 75, 70, [CodeCriticalityReason.Cryptography], 7)]);

        var result = await new CoverageCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task CoverageCriticalityAnalyzer_DoesNotUseAmbiguousFileNameMatch()
    {
        var context = CreateContext(
            [
                new CoverageFileInfo("src/A/Service.cs", 0.95, null, 19, 20, null, null),
                new CoverageFileInfo("src/B/Service.cs", 0.90, null, 18, 20, null, null)
            ],
            [new CodeCriticalityFile("src/C/Service.cs", 75, 70, [CodeCriticalityReason.Authentication], 7)]);

        var result = await new CoverageCriticalityAnalyzer().AnalyzeAsync(
            context,
            CancellationToken.None);

        Assert.Contains(
            result.Findings,
            finding => finding.RuleId == "TRUST-CODE007" &&
                       finding.Message.Contains("missing", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CoverageCriticalityAnalyzer_SkipsWhenCoverageIsUnknown()
    {
        var context = new AnalysisContext(".", ".", AnalysisDepth.Deep);
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, new CoverageArtifact([], [], new Dictionary<string, string>())));
        context.AddArtifact(new AnalyzerArtifact(CodeCriticalityArtifact.ArtifactKey, new CodeCriticalityArtifact(
            [new CodeCriticalityFile("src/AuthService.cs", 75, 70, [CodeCriticalityReason.Authentication], 2)],
            new Dictionary<string, string>())));

        var result = await new CoverageCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    private static AnalysisContext CreateContext(IReadOnlyList<CoverageFileInfo> coverageFiles, IReadOnlyList<CodeCriticalityFile> criticalFiles)
    {
        var context = new AnalysisContext(".", ".", AnalysisDepth.Deep);
        context.AddArtifact(new AnalyzerArtifact(CoverageArtifact.ArtifactKey, new CoverageArtifact(
            [new CoverageReportInfo("coverage.xml", CoverageReportFormat.Cobertura, 0.8, null, 8, 10, null, null)],
            coverageFiles,
            new Dictionary<string, string>())));
        context.AddArtifact(new AnalyzerArtifact(CodeCriticalityArtifact.ArtifactKey, new CodeCriticalityArtifact(
            criticalFiles,
            new Dictionary<string, string>())));
        return context;
    }
}

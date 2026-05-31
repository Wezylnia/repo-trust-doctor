using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class RepositoryHealthAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReportsMissingLicense()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO002");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsMissingChangelog()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO009");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportChangelogWhenExists()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), "History of changes");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO009");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsReadmeMissingInstallationAndUsage_WhenKeywordsAreMissing()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project Name\nThis is a simple project without instructions.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO010");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO011");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportReadmeMissingInstallationAndUsage_WhenKeywordsArePresent()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Setup\nRun `npm install`.\n## Usage\nTo run the project: `npm start`.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO010");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO011");
    }
}

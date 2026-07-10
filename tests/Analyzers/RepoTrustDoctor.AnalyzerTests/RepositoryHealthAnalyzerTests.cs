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

    [Theory]
    [InlineData("LICENSE.txt")]
    [InlineData("LICENSE.rst")]
    [InlineData("LICENCE")]
    [InlineData("COPYING")]
    [InlineData("COPYING.md")]
    [InlineData("COPYRIGHT")]
    public async Task AnalyzeAsync_DoesNotReportMissingLicense_WhenCommonLicenseFileExists(string fileName)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");
        File.WriteAllText(Path.Combine(fixture.Path, fileName), "license text");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO002");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotTreatLicenseHeaderAsLicenseFile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# sample");
        File.WriteAllText(Path.Combine(fixture.Path, "LICENSE_HEADER"), "copyright header");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO002");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportMissingReadme_WhenReadmeRstExists()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.rst"), "Project\n=======\n\nGetting started and usage.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO001");
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
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Getting Started\nRun `npm install`.\n## Usage\nTo run the project: `npm start`.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO010");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO011");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO012");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsMissingQuickStart_WhenReadmeHasInstallAndUsageOnly()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Installation\nRun install.\n## Usage\nRun the app.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO012");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsMissingDocsFolder()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Getting Started\nInstall and use.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REPO013");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportMissingDocsFolder_WhenDocsExists()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs"));
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Getting Started\nInstall and use.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO013");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportMissingDocsFolder_WhenGuidesExists()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "guides"));
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n## Getting Started\nInstall and use.");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO013");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsBrokenLocalReadmeLink()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), """
        # Project
        ## Getting Started
        Install and use.
        See [missing docs](docs/missing.md).
        """);
        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs"));

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REPO014");
        Assert.Equal(4, finding.Evidence[0].LineNumber);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportExistingLocalReadmeLinkOrExternalLinks()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs"));
        File.WriteAllText(Path.Combine(fixture.Path, "docs", "usage.md"), "# Usage");
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), """
        # Project
        ## Getting Started
        Install and use.
        See [usage](docs/usage.md) and [site](https://example.com).
        """);

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO014");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportReadmeLinksOutsideRepositoryWithSharedPathPrefix()
    {
        using var fixture = TemporaryRepository.Create();
        var siblingName = Path.GetFileName(fixture.Path) + "-other";
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), $"""
        # Project
        ## Getting Started
        Install and use.
        See [outside](../{siblingName}/missing.md).
        """);

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO014");
    }

    [Fact]
    public async Task AnalyzeAsync_MalformedPercentEncodedReadmeLinkDoesNotThrow()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), """
        # Project
        ## Getting Started
        Install and use.
        See [bad](docs/%zz.md).
        """);

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REPO014");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotTreatIgnoredNodeModulesAsTheRepositoryToolchain()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "# Project\n\nInstallation and usage.");
        var nestedDependency = Path.Combine(fixture.Path, "node_modules", "example");
        Directory.CreateDirectory(nestedDependency);
        File.WriteAllText(Path.Combine(nestedDependency, "package.json"), "{}");

        var analyzer = new RepositoryHealthAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.IdentityKey == "rep023|npm");
    }
}

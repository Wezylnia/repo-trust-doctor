using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitHubActionsBasicAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReportsUnpinnedThirdPartyAction()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA005");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsSelfHostedRunner()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: [self-hosted, linux]
            steps:
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA006");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportUbuntuRunner()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA006");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsUnsafeCheckout()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA007" && finding.Confidence == Confidence.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportSafeCheckout()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
                with:
                  persist-credentials: false
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA007");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsShellInjection()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA008" && finding.Confidence == Confidence.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportSafeShellVariables()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo "$PR_TITLE"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA008");
    }
}

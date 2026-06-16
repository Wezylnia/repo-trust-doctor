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
    public async Task AnalyzeAsync_AggregatesRepeatedUnpinnedActionReferences()
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
              - uses: actions/checkout@v4
        """);
        File.WriteAllText(Path.Combine(workflowDirectory, "lint.yml"), """
        name: lint
        on: [push]
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-GHA005");
        Assert.Contains("used 3 times", finding.Evidence[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_KeepsDifferentUnpinnedActionsAsSeparateFindings()
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
              - uses: actions/setup-dotnet@v4
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Equal(2, result.Findings.Count(finding => finding.RuleId == "TRUST-GHA005"));
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
    public async Task AnalyzeAsync_AggregatesUnsafeCheckoutReferences()
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
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
        """);
        File.WriteAllText(Path.Combine(workflowDirectory, "lint.yml"), """
        name: lint
        on: [push]
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-GHA007");
        Assert.Contains("used 3 times", finding.Evidence[0].Message, StringComparison.Ordinal);
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
    public async Task AnalyzeAsync_DoesNotReportSafeCheckoutWhenPersistCredentialsIsDeepInWithBlock()
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
              - name: Checkout
                uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
                with:
                  repository: owner/repository
                  ref: main
                  path: source
                  fetch-depth: 0
                  submodules: recursive
                  lfs: true
                  clean: true
                  persist-credentials: false
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA007");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotBorrowPersistCredentialsFromLaterCheckoutStep()
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
              - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
                with:
                  persist-credentials: false
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-GHA007");
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

    [Fact]
    public async Task AnalyzeAsync_ReportsReleasePublishWithoutTestDependency()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "release.yml"), """
        name: release
        on:
          push:
            tags: ["v*"]
        permissions:
          contents: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: gh release create "$GITHUB_REF_NAME"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA009" && finding.Confidence == Confidence.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportReleasePublishWithTestDependency()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "release.yml"), """
        name: release
        on:
          push:
            tags: ["v*"]
        permissions:
          contents: write
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
          publish:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: gh release create "$GITHUB_REF_NAME"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsBroadArtifactUploadPath()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@2541b1294d2704b0964813337f33b291d3f8596b
                with:
                  path: .
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA010" && finding.Confidence == Confidence.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportNarrowArtifactUploadPath()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@2541b1294d2704b0964813337f33b291d3f8596b
                with:
                  path: artifacts/package.zip
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA010");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsHardcodedSecretInEnv()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PASSWORD: supersecretvalue123
                run: echo "deploying"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-GHA013");
        Assert.Equal(Confidence.Medium, finding.Confidence);
        Assert.Contains("PASSWORD", finding.Evidence[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportSecretExpressionAsHardcodedSecret()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PASSWORD: ${{ secrets.DEPLOY_PASSWORD }}
                run: echo "deploying"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA013");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportReadOnlyPermissionsAsUnrestricted()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
          actions: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-GHA011");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsMatrixInjection()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            strategy:
              matrix:
                version: [1, 2, 3]
            runs-on: ubuntu-latest
            steps:
              - run: echo "version is ${{ matrix.version }}"
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA014");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsMatrixInjectionInMultilineRunBlock()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        permissions:
          contents: read
        jobs:
          test:
            strategy:
              matrix:
                version: [1, 2, 3]
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "building"
                  echo "version is ${{ matrix.version }}"
        """);

        var result = await new GitHubActionsBasicAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-GHA014");
        Assert.Equal(14, finding.Evidence[0].LineNumber);
    }

    // ── GHA015: pull_request_target + secrets ─────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DetectsPrTargetWithCheckout()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "pr.yml"), """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  repository: ${{ github.event.pull_request.head.repo.full_name }}
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: echo done
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA015");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA003");
    }

    [Fact]
    public async Task AnalyzeAsync_PrTargetDefaultCheckout_NoGHA015()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "pr.yml"), "on: [pull_request_target]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo done\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA015");
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA003" && f.Severity == Severity.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_PrTargetLabelOnly_NoGHA015()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "label.yml"), "on: [pull_request_target]\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v4\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA015");
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsWorkflowWritePerms()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "permissions:\n  contents: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA016");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA011");
    }

    [Fact]
    public async Task AnalyzeAsync_IssuesWorkflowWriteScope_ReportsGHA016()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "permissions:\n  issues: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA016");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA011");
    }

    [Fact]
    public async Task AnalyzeAsync_JobLevelWritePermsAtFileStart_NoWorkflowWriteFindings()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), """
        jobs:
          publish:
            permissions:
              contents: write
            runs-on: ubuntu-latest
            steps: []
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA011");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA016");
    }

    [Fact]
    public async Task AnalyzeAsync_ReadOnlyTopPerms_NoGHA016()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "permissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA016");
    }

    [Fact]
    public async Task AnalyzeAsync_IdTokenWriteWithReadContents_NoWorkflowWriteFindings()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "deploy.yml"), """
        permissions:
          id-token: write
          contents: read
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps: []
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA011");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA016");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsBroadCachePath()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: .\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA017");
    }

    [Fact]
    public async Task AnalyzeAsync_PublishJobNeedsTest_NoGHA009()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "release.yml"), """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
          publish:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task AnalyzeAsync_PublishJobTransitivelyNeedsTest_NoGHA009()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "release.yml"), """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
          build:
            needs: test
            runs-on: ubuntu-latest
            steps: []
          publish:
            needs: build
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task AnalyzeAsync_PublishJobNeedsBlockList_NoGHA009()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "release.yml"), """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
          build:
            runs-on: ubuntu-latest
            steps: []
          publish:
            needs:
              - test
              - build
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task AnalyzeAsync_UnrelatedJobNeedsTest_DoesNotSatisfyPublishJob()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "release.yml"), """
        jobs:
          lint:
            needs: test
            runs-on: ubuntu-latest
            steps: []
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task AnalyzeAsync_OnePublishJobWithoutValidation_StillReportsGHA009()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "release.yml"), """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
          package:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: dotnet nuget push package.nupkg
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f =>
            f.RuleId == "TRUST-GHA009" &&
            f.Evidence.Any(evidence => evidence.Message.Contains("publish", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task AnalyzeAsync_NarrowCachePath_NoGHA017()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: ~/.npm\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA017");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsLatestContainerImage()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "jobs:\n  build:\n    container:\n      image: node:latest\n    steps: []\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHA018");
    }

    [Fact]
    public async Task AnalyzeAsync_DigestPinnedContainer_NoGHA018()
    {
        using var fixture = TemporaryRepository.Create();
        var dir = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "ci.yml"), "jobs:\n  build:\n    container:\n      image: node@sha256:abc123\n    steps: []\n");

        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHA018");
    }

    [Fact]
    public async Task AnalyzeAsync_RegistryPortWithoutContainerTag_ReportsGHA018()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, "ci.yml"), """
        name: ci
        on: [push]
        jobs:
          build:
            runs-on: ubuntu-latest
            container:
              image: registry.example:5000/team/service
            steps:
              - run: echo done
        """);

        var result = await new GitHubActionsBasicAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-GHA018");
    }
}

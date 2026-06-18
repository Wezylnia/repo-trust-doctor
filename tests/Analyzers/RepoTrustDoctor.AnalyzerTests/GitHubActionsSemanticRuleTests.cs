using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitHubActionsSemanticRuleTests
{
    // TRUST-GHA019 tests
    [Fact]
    public async Task GHA019_ExternalReusableWorkflow_AtBranch()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          call:
            uses: owner/repo/.github/workflows/build.yml@main
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA019");
        var finding = findings.First(f => f.RuleId == "TRUST-GHA019");
        Assert.Contains("Mutable reusable workflow reference", finding.Title);
    }

    [Fact]
    public async Task GHA019_ExternalReusableWorkflow_AtTag()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          call:
            uses: owner/repo/.github/workflows/build.yml@v1
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA019");
    }

    [Fact]
    public async Task GHA019_ExternalReusableWorkflow_AtSha_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          call:
            uses: owner/repo/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA019");
    }

    [Fact]
    public async Task GHA019_LocalReusableWorkflow_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          call:
            uses: ./.github/workflows/build.yml
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA019");
    }

    // TRUST-GHA020 tests
    [Fact]
    public async Task GHA020_ValidationStep_ContinueOnError()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Run security scan
                run: echo scan
                continue-on-error: true
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA020");
    }

    [Fact]
    public async Task GHA020_ValidationJob_ContinueOnError()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          run-tests:
            runs-on: ubuntu-latest
            continue-on-error: true
            steps:
              - run: echo test
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA020");
    }

    [Fact]
    public async Task GHA020_UnrelatedExperimentalJob_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          experimental:
            runs-on: ubuntu-latest
            continue-on-error: true
            steps:
              - run: echo experimental
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA020");
    }

    // TRUST-GHA021 tests
    [Fact]
    public async Task GHA021_ReleaseJob_TransitiveDependency()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          build:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: echo build
          publish:
            needs: build
            if: always()
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task GHA021_ReleaseJob_NoDependency()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          publish:
            if: always()
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task GHA021_ReleaseJob_WithAlways()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          publish:
            needs: test
            if: always()
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA021");
    }

    // TRUST-GHA022 tests
    [Fact]
    public async Task GHA022_CacheKey_WithPRTitle()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  key: ${{ github.event.pull_request.title }}
                  path: node_modules
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA022");
    }

    [Fact]
    public async Task GHA022_CacheKey_WithSha_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  key: ${{ runner.os }}-${{ github.sha }}
                  path: node_modules
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA022");
    }

    // Migrated TRUST-GHA009 tests
    [Fact]
    public async Task GHA009_ReleaseJob_WithTestDependency()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          publish:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task GHA009_ReleaseJob_WithoutTestDependency()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task GHA009_ReleaseJob_WithTransitiveDependency()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          unit-test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
          build:
            needs: unit-test
            runs-on: ubuntu-latest
            steps:
              - run: echo build
          publish:
            needs: build
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
    }

    // Identity key stability
    [Fact]
    public async Task SemanticFindings_HaveStableIdentityKeys()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          call:
            uses: owner/repo/.github/workflows/build.yml@main
        """);

        var findings1 = await ScanAsync(fixture);
        var findings2 = await ScanAsync(fixture);

        Assert.Equal(findings1.Count, findings2.Count);
        for (var i = 0; i < findings1.Count; i++)
        {
            Assert.Equal(findings1[i].RuleId, findings2[i].RuleId);
            Assert.Equal(findings1[i].Fingerprint, findings2[i].Fingerprint);
        }
    }

    private static TemporaryRepository CreateWorkflow(string fileName, string content)
    {
        var fixture = TemporaryRepository.Create();
        var workflowDirectory = Path.Combine(fixture.Path, ".github", "workflows");
        Directory.CreateDirectory(workflowDirectory);
        File.WriteAllText(Path.Combine(workflowDirectory, fileName), content);
        return fixture;
    }

    private static async Task<IReadOnlyList<Finding>> ScanAsync(TemporaryRepository fixture)
    {
        var analyzer = new GitHubActionsBasicAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast),
            CancellationToken.None);
        return result.Findings;
    }
}

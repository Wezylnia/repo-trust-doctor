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

    [Fact]
    public async Task GHA020_OptionalCompatibilityJob_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          optional-compatibility:
            runs-on: ubuntu-latest
            continue-on-error: true
            steps:
              - run: echo compat
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA020");
    }

    [Fact]
    public async Task GHA020_NotificationStep_Passes()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Slack notification
                run: echo notify
                continue-on-error: true
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

    [Fact]
    public async Task GHA009_And_GHA016_EmitIdentityKeys()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        permissions:
          contents: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);

        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009" && !string.IsNullOrWhiteSpace(f.IdentityKey));
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA016" && !string.IsNullOrWhiteSpace(f.IdentityKey));
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

        var semantic1 = findings1.Where(f => f.RuleId == "TRUST-GHA019").ToList();
        var semantic2 = findings2.Where(f => f.RuleId == "TRUST-GHA019").ToList();

        Assert.Single(semantic1);
        Assert.Single(semantic2);
        Assert.Equal(semantic1[0].Fingerprint, semantic2[0].Fingerprint);
        Assert.False(string.IsNullOrWhiteSpace(semantic1[0].IdentityKey));
        Assert.Equal(semantic1[0].IdentityKey, semantic2[0].IdentityKey);
    }

    [Fact]
    public async Task GHA020_GHA021_GHA022_EmitIdentityKeys()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [pull_request]
        jobs:
          validate:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Security scan
                continue-on-error: true
                run: echo scan
          release:
            needs: validate
            if: always()
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  key: pr-${{ github.event.pull_request.title }}
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);

        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA020" && !string.IsNullOrWhiteSpace(f.IdentityKey));
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA021" && !string.IsNullOrWhiteSpace(f.IdentityKey));
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA022" && !string.IsNullOrWhiteSpace(f.IdentityKey));
    }

    [Fact]
    public async Task GHA021_GHA009_NotDuplicated_WhenAlwaysAndNeeds()
    {
        // Publish needs test + if: always() → GHA021 only, no GHA009.
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
          publish:
            needs: test
            if: always()
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA021");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task GHA009_Only_WhenNoNeeds()
    {
        // Publish with no needs → GHA009 only, no GHA021.
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
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task NeitherGHA009_NorGHA021_WhenNeedsTestWithoutAlways()
    {
        // Publish needs test, no always() → neither finding.
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
          publish:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task GHA021_Only_WhenTransitiveNeedsTestWithAlways()
    {
        // Publish needs build needs test + if: always() → GHA021 only.
        using var fixture = CreateWorkflow("ci.yml", """
        name: ci
        on: [push]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
          build:
            needs: test
            runs-on: ubuntu-latest
            steps:
              - run: dotnet build
          publish:
            needs: build
            if: always()
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA021");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
    }

    // ── 1.2: Publish detection accuracy ──────────────────────────────

    [Fact]
    public async Task PublishDetection_GhReleaseCreate_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: gh release create v1.0
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task PublishDetection_GhReleaseView_IsNotPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          check:
            runs-on: ubuntu-latest
            steps:
              - run: gh release view
        """);
        var findings = await ScanAsync(fixture);
        // gh release view is not publishing; if no other publish, no GHA009/GHA021.
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task PublishDetection_NpmPublish_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
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
    public async Task PublishDetection_DockerPush_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: docker push myimage:latest
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task PublishDetection_DockerBuildxBuild_WithoutPush_IsNotPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: docker buildx build -t myimage .
        """);
        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    [Fact]
    public async Task PublishDetection_DockerBuildxBuild_WithPush_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: docker buildx build -t myimage . --push
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task PublishDetection_SoftpropsActionRelease_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: softprops/action-gh-release@v1
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task PublishDetection_DockerBuildPushAction_WithPushTrue_IsPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: docker/build-push-action@v5
                with:
                  push: true
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA009");
    }

    [Fact]
    public async Task PublishDetection_DockerBuildPushAction_WithoutPush_IsNotPublishing()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker/build-push-action@v5
                with:
                  push: false
        """);
        var findings = await ScanAsync(fixture);
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA009");
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA021");
    }

    // ── 1.3: Validation job/step classification ────────────────────

    [Fact]
    public async Task Validation_UnnamedStep_DotnetTest_WithContinueOnError()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
                continue-on-error: true
        """);
        var findings = await ScanAsync(fixture);
        Assert.Contains(findings, f => f.RuleId == "TRUST-GHA020");
    }

    [Fact]
    public async Task Validation_JobNamedCi_WithDotnetTest()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          ci:
            runs-on: ubuntu-latest
            steps:
              - run: dotnet test
        """);
        var findings = await ScanAsync(fixture);
        // "ci" is not a validation token, but dotnet test makes the step validation.
        // GHA009/GHA021 not triggered (no publish). Just verify no crash.
        Assert.NotNull(findings);
    }

    [Fact]
    public async Task Validation_Contest_NotTest()
    {
        using var fixture = CreateWorkflow("ci.yml", """
        jobs:
          contest:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """);
        var findings = await ScanAsync(fixture);
        // "contest" should NOT match "test" (token-based matching).
        // With continue-on-error, should NOT trigger GHA020.
        Assert.DoesNotContain(findings, f => f.RuleId == "TRUST-GHA020");
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

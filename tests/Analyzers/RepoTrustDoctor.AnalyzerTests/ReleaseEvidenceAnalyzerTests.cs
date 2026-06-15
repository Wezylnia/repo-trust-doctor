using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class ReleaseEvidenceAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ChangelogMismatchReportsPackageVersionRules()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v2.0.0 - 2026-06-10
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        { "name": "example", "version": "1.0.0" }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotCompareNestedPackagesToRootChangelog()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v19.2.1
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "0.0.1",
          "private": false
        }
        """);
        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_UsesPackageSpecificRootChangelogEntry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## runtime@2.0.0
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "1.0.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL001");
        var mismatch = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REL004");
        Assert.Contains("2.0.0", mismatch.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_PackageSpecificRootSectionCanUseParentVersionHeading()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## 1.4.0

        ### @scope/runtime
        - Added a safer parser.
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "@scope/runtime",
          "version": "1.4.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_PackageBulletCanUseParentVersionHeading()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## 1.4.0

        - runtime: added a safer parser.
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "1.4.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_PackageMentionWithCalendarDateIsNotTreatedAsReleaseVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        runtime migration notes were updated on 2026.06.15.
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "1.4.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_FixedLernaWorkspaceUsesRootChangelog()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v2.0.0
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "name": "workspace-root",
          "private": true,
          "workspaces": ["packages/*"]
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "lerna.json"), """
        {
          "version": "1.0.0",
          "packages": ["packages/*"]
        }
        """);
        foreach (var name in new[] { "runtime", "compiler" })
        {
            var directory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", name));
            File.WriteAllText(Path.Combine(directory.FullName, "package.json"), $$"""
            {
              "name": "{{name}}",
              "version": "1.0.0"
            }
            """);
        }

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Equal(2, result.Findings.Count(finding => finding.RuleId == "TRUST-REL001"));
        Assert.Equal(2, result.Findings.Count(finding => finding.RuleId == "TRUST-REL004"));
    }

    [Fact]
    public async Task AnalyzeAsync_FixedLernaChangelogDoesNotApplyOutsideConfiguredPackages()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v2.0.0
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "lerna.json"), """
        {
          "version": "1.0.0",
          "packages": ["packages/*"]
        }
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        { "name": "runtime", "version": "1.0.0" }
        """);
        var toolDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "tools", "publisher"));
        File.WriteAllText(Path.Combine(toolDirectory.FullName, "package.json"), """
        { "name": "publisher", "version": "1.0.0" }
        """);
        var dotnetDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "src", "Tool"));
        File.WriteAllText(Path.Combine(dotnetDirectory.FullName, "Tool.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <Version>1.0.0</Version>
          </PropertyGroup>
        </Project>
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Equal(1, result.Findings.Count(finding => finding.RuleId == "TRUST-REL001"));
        Assert.Equal(1, result.Findings.Count(finding => finding.RuleId == "TRUST-REL004"));
        Assert.All(
            result.Findings.Where(finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004"),
            finding => Assert.Equal("packages/runtime/package.json", finding.Evidence[0].FilePath));
    }

    [Fact]
    public async Task AnalyzeAsync_FixedLernaHonorsNegatedPackagePatterns()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v2.0.0
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "lerna.json"), """
        {
          "version": "1.0.0",
          "packages": ["packages/*", "!packages/internal"]
        }
        """);
        foreach (var name in new[] { "runtime", "internal" })
        {
            var directory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", name));
            File.WriteAllText(Path.Combine(directory.FullName, "package.json"), $$"""
            { "name": "{{name}}", "version": "1.0.0" }
            """);
        }

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Equal(1, result.Findings.Count(finding => finding.RuleId == "TRUST-REL001"));
        Assert.Equal(1, result.Findings.Count(finding => finding.RuleId == "TRUST-REL004"));
        Assert.All(
            result.Findings.Where(finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004"),
            finding => Assert.Equal("packages/runtime/package.json", finding.Evidence[0].FilePath));
    }

    [Fact]
    public async Task AnalyzeAsync_IndependentVersionWorkspaceDoesNotUseGlobalRootVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v9.0.0
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "name": "workspace-root",
          "private": true,
          "workspaces": {
            "packages": ["packages/*"]
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "lerna.json"), """
        {
          "version": "independent",
          "packages": ["packages/*"]
        }
        """);
        var runtime = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(runtime.FullName, "package.json"), """
        { "name": "runtime", "version": "1.0.0" }
        """);
        var compiler = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "compiler"));
        File.WriteAllText(Path.Combine(compiler.FullName, "package.json"), """
        { "name": "compiler", "version": "2.0.0" }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_UnscopedPackageDoesNotUseScopedPackageReleaseEntry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## @scope/runtime@1.0.0
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "1.0.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportPrivateOrFixturePackageVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v19.2.1
        """);
        var privateDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "playground"));
        File.WriteAllText(Path.Combine(privateDirectory.FullName, "package.json"), """
        {
          "name": "playground",
          "version": "0.1.0",
          "private": true
        }
        """);
        var fixtureDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "fixtures", "dom"));
        File.WriteAllText(Path.Combine(fixtureDirectory.FullName, "package.json"), """
        {
          "name": "fixture",
          "version": "0.1.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }

    [Fact]
    public async Task AnalyzeAsync_UsesNestedChangelogForNestedPackage()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v19.2.1
        """);
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "runtime"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "CHANGELOG.md"), """
        # Runtime

        ## v2.0.0
        """);
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "name": "runtime",
          "version": "1.0.0"
        }
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REL004");
        Assert.Contains("2.0.0", finding.Message, StringComparison.Ordinal);
    }
}

public sealed class ReleaseArtifactEvidenceAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ArtifactWithoutIntegrityEvidenceReportsRules()
    {
        using var fixture = TemporaryRepository.Create();
        var dist = Directory.CreateDirectory(Path.Combine(fixture.Path, "dist"));
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip"), "synthetic");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_GitignoredRootArtifactDirectoryDoesNotReportArtifactRules()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".gitignore"), "artifacts/\n");
        var publish = Directory.CreateDirectory(Path.Combine(fixture.Path, "artifacts", "publish"));
        File.WriteAllText(Path.Combine(publish.FullName, "tool.zip"), "synthetic");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_ArtifactWithChecksumAndSbomDoesNotReportArtifactRules()
    {
        using var fixture = TemporaryRepository.Create();
        var dist = Directory.CreateDirectory(Path.Combine(fixture.Path, "dist"));
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip"), "synthetic");
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip.sha256"), "abc");
        File.WriteAllText(Path.Combine(dist.FullName, "sbom.cdx.json"), "{}");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_SignatureDoesNotCountAsChecksum()
    {
        using var fixture = TemporaryRepository.Create();
        var dist = Directory.CreateDirectory(Path.Combine(fixture.Path, "dist"));
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip"), "synthetic");
        File.WriteAllText(Path.Combine(dist.FullName, "tool.zip.sig"), "signature");
        File.WriteAllText(Path.Combine(dist.FullName, "sbom.cdx.json"), "{}");

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL003");
    }

    [Fact]
    public async Task AnalyzeAsync_ReleaseWorkflowWithoutIntegrityStepsReportsRule()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDir = Directory.CreateDirectory(Path.Combine(fixture.Path, ".github", "workflows"));
        File.WriteAllText(Path.Combine(workflowDir.FullName, "release.yml"), """
        name: release
        on:
          push:
            tags: ["v*"]
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REL005");
        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public async Task AnalyzeAsync_IntegrityWordsInCommentsDoNotSuppressRule()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDir = Directory.CreateDirectory(Path.Combine(fixture.Path, ".github", "workflows"));
        File.WriteAllText(Path.Combine(workflowDir.FullName, "release.yml"), """
        name: release
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              # TODO: add SBOM generation with syft and cosign
              - run: npm publish
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REL005");
    }

    [Fact]
    public async Task AnalyzeAsync_PublishWordsInCommentsDoNotCreateRule()
    {
        using var fixture = TemporaryRepository.Create();
        var workflowDir = Directory.CreateDirectory(Path.Combine(fixture.Path, ".github", "workflows"));
        File.WriteAllText(Path.Combine(workflowDir.FullName, "build.yml"), """
        name: build
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              # Future release command: npm publish
              - run: dotnet test
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REL005");
    }

    [Fact]
    public async Task AnalyzeAsync_PyprojectVersionIsReadOnlyFromPackageSections()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CHANGELOG.md"), """
        # Changelog

        ## v1.2.0
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [tool.some-plugin]
        version = "9.9.9"

        [project]# package metadata
        name = "example"
        version = "1.2.0"
        """);

        var result = await new ReleaseEvidenceAnalyzer().AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.DoesNotContain(
            result.Findings,
            finding => finding.RuleId is "TRUST-REL001" or "TRUST-REL004");
    }
}

using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyRiskAnalyzerTests
{
    [Fact]
    public async Task PackageMetadataAnalyzer_EmitsMetadataArtifact_FromFakeClient()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "safe-lib", "1.0.0")
        ]);
        var analyzer = new PackageMetadataAnalyzer([new FakeMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        var package = Assert.Single(metadata.Packages);
        Assert.Equal(nameof(DependencyScope.Production), package.Metadata?["dependency.scope"]);
        Assert.Equal("1", metadata.Metrics["dependency.metadata.package.count"]);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_SkipsExampleAndTestManifestPackages()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "production-lib", "1.0.0"),
            CreatePackage(DependencyEcosystem.Npm, "fixture-lib", "1.0.0", manifestPath: "packages/tool/__tests__/package.json"),
            CreatePackage(DependencyEcosystem.Npm, "playground-lib", "1.0.0", manifestPath: "playground/demo/package.json")
        ]);
        var analyzer = new PackageMetadataAnalyzer([new FakeMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        var package = Assert.Single(metadata.Packages);
        Assert.Equal("production-lib", package.Name);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_DeduplicatesPackagesWithoutLimitingDistinctLookups()
    {
        var packages = Enumerable.Range(0, 60)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, "shared-lib", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .Append(CreatePackage(DependencyEcosystem.Npm, "target-lib", "1.0.0", manifestPath: "target/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var analyzer = new PackageMetadataAnalyzer([new FakeMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        Assert.Contains(metadata.Packages, package => package.Name == "target-lib");
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_QueriesAllSupportedDistinctPackagesBeyondPreviousLimit()
    {
        var packages = Enumerable.Range(0, 75)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, $"package-{index}", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var client = new FakeMetadataClient(DependencyEcosystem.Npm);
        var analyzer = new PackageMetadataAnalyzer([client]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        Assert.Equal(75, metadata.Packages.Count);
        Assert.Equal("75", result.Metrics!["dependency.metadata.lookup.completed.count"]);
        Assert.Equal("0", result.Metrics["dependency.metadata.lookup.incomplete.count"]);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_PreservesCompletedLookupsWhenSoftBudgetExpires()
    {
        var packages = Enumerable.Range(0, 12)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, $"package-{index}", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var analyzer = new PackageMetadataAnalyzer(
            [new PartialMetadataClient(DependencyEcosystem.Npm)],
            TimeSpan.FromMilliseconds(100));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        Assert.Contains(metadata.Packages, package => package.Name == "package-0");
        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("completed", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("12", result.Metrics!["dependency.metadata.supported.count"]);
        Assert.NotEqual("0", result.Metrics["dependency.metadata.lookup.incomplete.count"]);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_QueriesMetadataWithBoundedParallelism()
    {
        var packages = Enumerable.Range(0, 12)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, $"package-{index}", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var client = new TrackingMetadataClient(DependencyEcosystem.Npm);
        var analyzer = new PackageMetadataAnalyzer([client]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == PackageMetadataArtifact.ArtifactKey);
        var metadata = Assert.IsType<PackageMetadataArtifact>(artifact.Value);
        Assert.Equal(12, metadata.Packages.Count);
        Assert.Equal(12, client.QueryCount);
        Assert.True(client.MaxObservedConcurrency > 1);
        Assert.True(client.MaxObservedConcurrency <= 8);
    }

    [Fact]
    public async Task PackageMetadataAnalyzer_PreservesParseWarningsFromParallelLookups()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "bad-lib", "1.0.0")
        ]);
        var analyzer = new PackageMetadataAnalyzer([new ThrowingMetadataClient(DependencyEcosystem.Npm)]);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("bad-lib", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_ReportsOutdatedAndDeprecatedPackages()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "old-lib", "1.0.0", "2.0.0", null, false, false, null, null, "MIT", null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "deprecated-lib", "1.0.0", "1.0.0", null, true, false, null, null, "MIT", null, "registry.npmjs.org")
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP015");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP016");
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_IgnoresPrereleaseLatestForStablePackage()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.NuGet, "stable-lib", "3.2.2", "4.0.0-pre.1", null, false, false, null, null, "MIT", null, "nuget.org")
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP015");
    }

    [Fact]
    public async Task PackageFreshnessAnalyzer_SkipsDevelopmentDependencies()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(
                DependencyEcosystem.NuGet,
                "xunit",
                "2.9.0",
                "3.0.0",
                null,
                true,
                false,
                null,
                null,
                "MIT",
                null,
                "nuget.org",
                new Dictionary<string, string> { ["dependency.scope"] = nameof(DependencyScope.Development) })
        ]);

        var result = await new PackageFreshnessAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_ReportsDirectVulnerabilityAndFixedVersion()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "vulnerable-lib", "1.0.0")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-test", [], "test advisory", Severity.High, ["2.0.0"], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-VULN001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-VULN003");
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_SkipsExampleAndTestManifestPackages()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "fixture-lib", "1.0.0", manifestPath: "playground/demo/package.json")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-test", [], "test advisory", Severity.High, ["2.0.0"], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_DeduplicatesSamePackageAdvisoryAcrossManifests()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Maven, "org.springframework.boot:spring-boot", "3.3.1", manifestPath: "module-a/pom.xml"),
            CreatePackage(DependencyEcosystem.Maven, "org.springframework.boot:spring-boot", "3.3.1", manifestPath: "module-b/pom.xml")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-duplicate", [], "duplicate advisory", Severity.High, ["3.3.2"], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-VULN001");
        Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-VULN003");
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_MergesAliasAdvisories()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "vulnerable-lib", "1.0.0")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory(
                "GHSA-example",
                ["CVE-2026-1234"],
                "GitHub advisory",
                Severity.High,
                ["1.1.0"],
                null,
                new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero)),
            new VulnerabilityAdvisory(
                "NPM-2026-1",
                ["CVE-2026-1234"],
                "Registry advisory with more detail",
                Severity.Critical,
                ["1.0.5"],
                null,
                new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero))
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var vulnerability = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-VULN001");
        Assert.Equal(Severity.Critical, vulnerability.Severity);
        Assert.Contains("CVE-2026-1234", vulnerability.Message, StringComparison.Ordinal);
        Assert.Contains("GHSA-example", vulnerability.Tags!);
        Assert.Contains("NPM-2026-1", vulnerability.Tags!);

        var fixedVersion = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-VULN003");
        Assert.Contains("1.0.5", fixedVersion.Evidence[0].Message, StringComparison.Ordinal);
        Assert.Contains("1.1.0", fixedVersion.Evidence[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_MergesTransitivelyConnectedAliases()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "vulnerable-lib", "1.0.0")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-chain", ["CVE-2026-5678"], "first", Severity.High, [], null, null),
            new VulnerabilityAdvisory("NPM-CHAIN", ["GHSA-chain"], "second", Severity.High, [], null, null),
            new VulnerabilityAdvisory("OSV-CHAIN", ["NPM-CHAIN"], "third", Severity.High, [], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-VULN001");
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_ReportsDirectBeforeDuplicateTransitive()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "shared-lib", "1.0.0", DependencyScope.Production, "transitive/package.json") with { IsDirect = false },
            CreatePackage(DependencyEcosystem.Npm, "shared-lib", "1.0.0", DependencyScope.Production, "direct/package.json")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-direct", [], "duplicate advisory", Severity.High, [], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings);
        Assert.Equal("TRUST-VULN001", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_DeduplicatesPackagesWithoutDroppingLaterPackages()
    {
        var packages = Enumerable.Range(0, 60)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, "shared-lib", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .Append(CreatePackage(DependencyEcosystem.Npm, "target-lib", "1.0.0", manifestPath: "target/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var analyzer = new DependencyVulnerabilityAnalyzer(new FakeOsvClient([
            new VulnerabilityAdvisory("GHSA-limit", [], "limit advisory", Severity.High, [], null, null)
        ]));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.Message.Contains("target-lib", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_QueriesAllSupportedPackagesBeyondPreviousLimit()
    {
        var packages = Enumerable.Range(0, 175)
            .Select(index => CreatePackage(
                DependencyEcosystem.Npm,
                $"package-{index}",
                "1.0.0",
                manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var client = new TrackingOsvClient();
        var analyzer = new DependencyVulnerabilityAnalyzer(client);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(175, client.QueryCount);
        Assert.Equal("175", result.Metrics!["dependency.vulnerability.lookup.completed.count"]);
        Assert.Equal("0", result.Metrics["dependency.vulnerability.lookup.incomplete.count"]);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_QueriesAdvisoriesWithBoundedParallelism()
    {
        var packages = Enumerable.Range(0, 220)
            .Select(index => CreatePackage(DependencyEcosystem.Npm, $"package-{index}", "1.0.0", manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var client = new TrackingOsvClient();
        var analyzer = new DependencyVulnerabilityAnalyzer(client);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        Assert.Equal(220, client.QueryCount);
        Assert.True(client.MaxObservedConcurrency > 1);
        Assert.True(client.MaxObservedConcurrency <= 4);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_PreservesCompletedBatchesWhenSoftBudgetExpires()
    {
        var packages = Enumerable.Range(0, 250)
            .Select(index => CreatePackage(
                DependencyEcosystem.Npm,
                $"package-{index}",
                "1.0.0",
                manifestPath: $"module-{index}/package.json"))
            .ToArray();
        var context = CreateContextWithInventory(packages);
        var analyzer = new DependencyVulnerabilityAnalyzer(
            new PartialBatchOsvClient(),
            TimeSpan.FromMilliseconds(100));

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("completed", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("100", result.Metrics!["dependency.vulnerability.lookup.completed.count"]);
        Assert.Equal("150", result.Metrics["dependency.vulnerability.lookup.incomplete.count"]);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_ReportsUnsupportedEcosystemCoverage()
    {
        var context = CreateContextWithInventory([
            CreatePackage(DependencyEcosystem.Npm, "supported", "1.0.0"),
            CreatePackage(DependencyEcosystem.Cpp, "unsupported", "1.0.0")
        ]);
        var analyzer = new DependencyVulnerabilityAnalyzer(new NpmOnlyOsvClient());

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal("2", result.Metrics!["dependency.vulnerability.candidate.count"]);
        Assert.Equal("1", result.Metrics["dependency.vulnerability.supported.count"]);
        Assert.Equal("1", result.Metrics["dependency.vulnerability.unsupported.count"]);
    }

    [Fact]
    public async Task DependencyVulnerabilityAnalyzer_DoesNotReportVersionRangesAsChecked()
    {
        var package = CreatePackage(DependencyEcosystem.Npm, "range-package", "^1.0.0") with
        {
            IsVersionPinned = false
        };
        var context = CreateContextWithInventory([package]);
        var client = new TrackingOsvClient();
        var analyzer = new DependencyVulnerabilityAnalyzer(client);

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(0, client.QueryCount);
        Assert.Equal("1", result.Metrics!["dependency.vulnerability.unpinned.count"]);
        Assert.Equal("0", result.Metrics["dependency.vulnerability.lookup.completed.count"]);
    }

    [Fact]
    public async Task DependencyLicenseAnalyzer_ReportsMissingUnknownAndCopyleftLicenses()
    {
        var context = CreateContextWithMetadata([
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "missing", "1.0.0", "1.0.0", null, false, false, null, null, null, null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "unknown", "1.0.0", "1.0.0", null, false, false, null, null, "custom", null, "registry.npmjs.org"),
            new PackageRegistryMetadata(DependencyEcosystem.Npm, "copyleft", "1.0.0", "1.0.0", null, false, false, null, null, "GPL-3.0-only", null, "registry.npmjs.org")
        ]);

        var result = await new DependencyLicenseAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC001");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-LIC003");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_ReportsMissingRepositoryAndMixedNuGetSources()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "NuGet.config"), """
        <configuration>
          <packageSources>
            <add key="nuget" value="https://api.nuget.org/v3/index.json" />
            <add key="internal" value="https://packages.example.test/index.json" />
          </packageSources>
        </configuration>
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, new DependencyInventoryArtifact(
            [],
            [],
            [],
            [
                new DependencyPackageSourceInfo(DependencyEcosystem.NuGet, "nuget", "https://api.nuget.org/v3/index.json", "NuGet.config"),
                new DependencyPackageSourceInfo(DependencyEcosystem.NuGet, "internal", "https://packages.example.test/index.json", "NuGet.config")
            ],
            new Dictionary<string, string>())));
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.Npm, "microsoft-helper", "1.0.0", "1.0.0", null, false, false, null, null, "MIT", null, "registry.npmjs.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN003");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN004");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN002");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_SkipsMissingRepositoryForDevelopmentPackages()
    {
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.NuGet, "xunit.v3", "3.2.2", DependencyScope.Development)
        ]);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.NuGet, "xunit.v3", "3.2.2", "3.2.2", null, false, false, null, null, "MIT", null, "nuget.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN003");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_DoesNotCompareThirdPartyDependencyRepositoryToTarget()
    {
        var context = new AnalysisContext(".", "https://github.com/example/application", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(
            [new PackageRegistryMetadata(DependencyEcosystem.Npm, "react", "19.0.0", "19.0.0", null, false, false, "https://github.com/facebook/react", null, "MIT", null, "registry.npmjs.org")],
            new Dictionary<string, string>())));

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN001");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_RequiresMatchingNpmScopeRegistry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), """
        @other:registry=https://npm.example.test/
        """);
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.Npm, "@internal/widget", "1.0.0")
        ], fixture.Path);

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN005");
    }

    [Fact]
    public async Task PackageOriginAnalyzer_AcceptsMatchingNpmScopeRegistry()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), """
        @internal:registry = https://npm.example.test/
        """);
        var context = CreateContextWithInventory(
        [
            CreatePackage(DependencyEcosystem.Npm, "@internal/widget", "1.0.0")
        ], fixture.Path);

        var result = await new PackageOriginAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-ORIGIN005");
    }

    private static AnalysisContext CreateContextWithInventory(IReadOnlyList<DependencyPackageInfo> packages, string repositoryPath = ".")
    {
        var context = new AnalysisContext(repositoryPath, repositoryPath, AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(DependencyInventoryArtifact.ArtifactKey, new DependencyInventoryArtifact([], [], packages, [], new Dictionary<string, string>())));
        return context;
    }

    private static AnalysisContext CreateContextWithMetadata(IReadOnlyList<PackageRegistryMetadata> packages)
    {
        var context = new AnalysisContext(".", ".", AnalysisDepth.Standard);
        context.AddArtifact(new AnalyzerArtifact(PackageMetadataArtifact.ArtifactKey, new PackageMetadataArtifact(packages, new Dictionary<string, string>())));
        return context;
    }

    private static DependencyPackageInfo CreatePackage(
        DependencyEcosystem ecosystem,
        string name,
        string version,
        DependencyScope scope = DependencyScope.Production,
        string manifestPath = "manifest") =>
        new(ecosystem, name, version, scope, manifestPath, null, true, true, false);

    private sealed class FakeMetadataClient(DependencyEcosystem ecosystem) : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem { get; } = ecosystem;

        public Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken) =>
            Task.FromResult<PackageRegistryMetadata?>(new PackageRegistryMetadata(package.Ecosystem, package.Name, package.Version, package.Version, null, false, false, "https://github.com/example/repo", null, "MIT", null, "fake"));
    }

    private sealed class TrackingMetadataClient(DependencyEcosystem ecosystem) : IPackageMetadataClient
    {
        private int currentConcurrency;
        private int maxObservedConcurrency;
        private int queryCount;

        public DependencyEcosystem Ecosystem { get; } = ecosystem;

        public int MaxObservedConcurrency => Volatile.Read(ref maxObservedConcurrency);

        public int QueryCount => Volatile.Read(ref queryCount);

        public async Task<PackageRegistryMetadata?> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref queryCount);
            var current = Interlocked.Increment(ref currentConcurrency);
            UpdateMaxObserved(current);

            try
            {
                await Task.Delay(50, cancellationToken);
                return new PackageRegistryMetadata(package.Ecosystem, package.Name, package.Version, package.Version, null, false, false, "https://github.com/example/repo", null, "MIT", null, "fake");
            }
            finally
            {
                Interlocked.Decrement(ref currentConcurrency);
            }
        }

        private void UpdateMaxObserved(int current)
        {
            while (true)
            {
                var observed = Volatile.Read(ref maxObservedConcurrency);
                if (current <= observed)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref maxObservedConcurrency, current, observed) == observed)
                {
                    return;
                }
            }
        }
    }

    private sealed class ThrowingMetadataClient(DependencyEcosystem ecosystem) : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem { get; } = ecosystem;

        public Task<PackageRegistryMetadata?> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken) =>
            throw new FormatException("bad registry payload");
    }

    private sealed class PartialMetadataClient(DependencyEcosystem ecosystem) : IPackageMetadataClient
    {
        public DependencyEcosystem Ecosystem { get; } = ecosystem;

        public async Task<PackageRegistryMetadata?> GetMetadataAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            if (package.Name != "package-0")
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }

            return new PackageRegistryMetadata(
                package.Ecosystem,
                package.Name,
                package.Version,
                package.Version,
                null,
                false,
                false,
                "https://github.com/example/repo",
                null,
                "MIT",
                null,
                "fake");
        }
    }

    private sealed class FakeOsvClient(IReadOnlyList<VulnerabilityAdvisory> advisories) : IOsvAdvisoryClient
    {
        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(DependencyPackageInfo package, CancellationToken cancellationToken) =>
            Task.FromResult(advisories);
    }

    private sealed class TrackingOsvClient : IOsvAdvisoryClient
    {
        private int currentConcurrency;
        private int maxObservedConcurrency;
        private int queryCount;

        public int MaxObservedConcurrency => Volatile.Read(ref maxObservedConcurrency);

        public int QueryCount => Volatile.Read(ref queryCount);

        public async Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref queryCount);
            var current = Interlocked.Increment(ref currentConcurrency);
            UpdateMaxObserved(current);

            try
            {
                await Task.Delay(5, cancellationToken);
                return [];
            }
            finally
            {
                Interlocked.Decrement(ref currentConcurrency);
            }
        }

        private void UpdateMaxObserved(int current)
        {
            while (true)
            {
                var observed = Volatile.Read(ref maxObservedConcurrency);
                if (current <= observed)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref maxObservedConcurrency, current, observed) == observed)
                {
                    return;
                }
            }
        }
    }

    private sealed class PartialBatchOsvClient : IOsvAdvisoryClient
    {
        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<VulnerabilityAdvisory>>([]);

        public async Task<OsvBatchQueryResult> QueryBatchAsync(
            IReadOnlyList<DependencyPackageInfo> packages,
            CancellationToken cancellationToken)
        {
            if (packages[0].Name != "package-0")
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }

            return new OsvBatchQueryResult(
                packages.Select(package => new OsvPackageQueryResult(package, [])).ToArray(),
                true,
                []);
        }
    }

    private sealed class NpmOnlyOsvClient : IOsvAdvisoryClient
    {
        public bool SupportsEcosystem(DependencyEcosystem ecosystem) =>
            ecosystem == DependencyEcosystem.Npm;

        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<VulnerabilityAdvisory>>([]);
    }
}

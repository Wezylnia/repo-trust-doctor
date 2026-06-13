using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryAdditionalEcosystemTests
{
    [Fact]
    public async Task AnalyzeAsync_GoModWithoutGoSum_ReportsDep022()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require github.com/gin-gonic/gin v1.9.1
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP022");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("go.mod", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModWithGoSum_DoesNotReportDep022()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP022");
    }

    [Fact]
    public async Task AnalyzeAsync_GoModWithReplaceDirective_ReportsDep023()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require github.com/gin-gonic/gin v1.9.1

        replace github.com/gin-gonic/gin => github.com/fork/gin v1.9.1-patched
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP023");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModWithMultipleReplaceDirectives_AggregatesDep023PerManifest()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        replace github.com/gin-gonic/gin => github.com/fork/gin v1.9.1-patched
        replace github.com/example/one => ../one
        replace github.com/example/two => ../two
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP023");
        Assert.Contains("3 replace directives", finding.Message, StringComparison.Ordinal);
        Assert.Contains("github.com/gin-gonic/gin", finding.Evidence[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModExactPinnedVersions_AreRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require (
            github.com/gin-gonic/gin v1.9.1
            github.com/stretchr/testify v1.8.4 // indirect
        )
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Go && m.Kind == "go.mod");
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Go && p.Name == "github.com/gin-gonic/gin" && p.IsVersionPinned);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Go && p.Name == "github.com/stretchr/testify" && !p.IsDirect);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP024");
    }

    [Fact]
    public async Task AnalyzeAsync_GoModPseudoVersion_ReportsDep025()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require github.com/example/lib v0.0.0-20240115120000-abcdef123456
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP025");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Contains("github.com/example/lib", finding.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP024");
        Assert.Contains(GetInventory(result).Packages, p => p.Name == "github.com/example/lib" && p.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModWithMultipleDirectPseudoVersions_AggregatesDep025PerManifest()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require (
            github.com/example/lib v0.0.0-20240115120000-abcdef123456
            github.com/example/other v1.2.3-20240115120000-bbcdef123456
        )
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP025");
        Assert.Contains("2 direct dependencies", finding.Message, StringComparison.Ordinal);
        Assert.Contains("github.com/example/lib", finding.Evidence[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModIndirectPseudoVersion_IsRecordedWithoutDep025()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require github.com/example/transitive v0.0.0-20240115120000-abcdef123456 // indirect
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "github.com/example/transitive" && package.Metadata?["pseudoVersion"] == "true");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP025");
    }

    [Theory]
    [InlineData("v1.2.3-rc.1")]
    [InlineData("v2.5.0+incompatible")]
    public async Task AnalyzeAsync_GoModSemverPrereleaseAndBuildMetadata_AreExactVersions(string version)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), $$"""
        module example.com/mymodule

        go 1.22

        require github.com/example/lib {{version}}
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP024");
        Assert.Contains(GetInventory(result).Packages, p => p.Name == "github.com/example/lib" && p.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_GoModNonExactVersion_ReportsDep024()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require github.com/example/lib v1.2
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP024");
        Assert.Contains("github.com/example/lib", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_GoMetrics_ReflectPackageCounts()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "go.sum"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "go.mod"), """
        module example.com/mymodule

        go 1.22

        require (
            github.com/gin-gonic/gin v1.9.1
            github.com/stretchr/testify v1.8.4 // indirect
        )
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Equal("1", inventory.Metrics["dependency.manifest.go.count"]);
        Assert.Equal("2", inventory.Metrics["dependency.package.go.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_CargoTomlWithoutCargoLock_ReportsDep026()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"
        version = "0.1.0"

        [dependencies]
        serde = "1.0"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP026");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        Assert.Equal("Cargo.toml", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_CargoTomlWithCargoLock_DoesNotReportDep026()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP026");
    }

    [Fact]
    public async Task AnalyzeAsync_CargoExactVersions_AreRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"
        version = "0.1.0"

        [dependencies]
        serde = "=1.0.210"
        tokio = { version = "=1.41.0", features = ["full"] }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Cargo && m.Kind == "Cargo.toml");
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cargo && p.Name == "serde" && p.IsVersionPinned);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cargo && p.Name == "tokio" && p.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP029");
    }

    [Fact]
    public async Task AnalyzeAsync_CargoDependencySubtable_DoesNotRecordMetadataKeysAsPackages()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies.serde]
        version = "=1.0.210"
        features = ["derive"]
        default-features = false
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cargo);
        Assert.Equal("serde", package.Name);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(inventory.Packages, p => p.Name is "version" or "features" or "default-features");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP029");
    }

    [Fact]
    public async Task AnalyzeAsync_CargoTargetDependencySubtable_RecordsCrateName()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [target.'cfg(windows)'.dependencies.windows-sys]
        version = "0.59.0"
        features = ["Win32_Foundation"]
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cargo && p.Name == "windows-sys");
        Assert.DoesNotContain(inventory.Packages, p => p.Name == "features");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP029");
    }

    [Fact]
    public async Task AnalyzeAsync_CargoNonExactVersionWithoutLockfile_ReportsDep029()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        serde = "1"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP029" && f.Message.Contains("serde", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_CargoBareSemverRequirementWithoutLockfile_ReportsDep029()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        serde = "1.0.210"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP029" && f.Message.Contains("serde", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_CargoGitDependency_ReportsDep027()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        mylib = { git = "https://github.com/example/mylib", branch = "main" }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP027" && f.Message.Contains("mylib", StringComparison.Ordinal));
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, p => p.Name == "mylib");
        Assert.Equal("git", package.Metadata?["sourceKind"]);
    }

    [Fact]
    public async Task AnalyzeAsync_CargoPathDependency_ReportsDep028()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        mylib = { path = "../mylib" }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP028" && f.Message.Contains("mylib", StringComparison.Ordinal));
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, p => p.Name == "mylib");
        Assert.Equal("path", package.Metadata?["sourceKind"]);
    }

    [Fact]
    public async Task AnalyzeAsync_CargoDevAndBuildDependencies_AreScopedCorrectly()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        serde = "1.0.210"

        [dev-dependencies]
        tokio-test = "1.0.0"

        [build-dependencies]
        cc = "1.0.0"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Name == "serde" && p.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, p => p.Name == "tokio-test" && p.Scope == DependencyScope.Development);
        Assert.Contains(inventory.Packages, p => p.Name == "cc" && p.Scope == DependencyScope.Development);
    }

    [Fact]
    public async Task AnalyzeAsync_CargoMetrics_ReflectPackageCounts()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.toml"), """
        [package]
        name = "mycrate"

        [dependencies]
        serde = "1.0.210"
        tokio = "1.41.0"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Equal("1", inventory.Metrics["dependency.manifest.cargo.count"]);
        Assert.Equal("2", inventory.Metrics["dependency.package.cargo.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerJsonWithoutComposerLock_ReportsDep031()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "type": "project",
            "require": {
                "php": ">=8.1",
                "monolog/monolog": "^3.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP031");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        Assert.Equal("composer.json", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerJsonWithComposerLock_DoesNotReportDep031()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "require": {
                "monolog/monolog": "3.5.0"
            }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "composer.lock"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP031");
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerLibraryWithoutComposerLock_DoesNotReportApplicationLockFindings()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "name": "vendor/library",
            "require": {
                "monolog/monolog": "^3.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId is "TRUST-DEP031" or "TRUST-DEP032");
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerNonExactConstraintsWithoutLock_AggregatesDep032()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "type": "project",
            "require": {
                "php": ">=8.1",
                "ext-json": "*",
                "monolog/monolog": "^3.0"
            },
            "require-dev": {
                "phpunit/phpunit": "~10.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP032");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Contains("monolog/monolog", evidence.Message, StringComparison.Ordinal);
        Assert.Contains("phpunit/phpunit", evidence.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("ext-json", evidence.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerNonExactConstraintsWithLock_DoNotReportDep032()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.lock"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "type": "project",
            "require": {
                "monolog/monolog": "^3.0"
            },
            "require-dev": {
                "phpunit/phpunit": "~10.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP032");
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerExactVersion_IsRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.lock"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "require": {
                "monolog/monolog": "3.5.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Composer && m.Kind == "composer.json");
        var package = Assert.Single(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Composer && p.Name == "monolog/monolog");
        Assert.True(package.IsVersionPinned);
        Assert.Equal(DependencyScope.Production, package.Scope);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP032");
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerDevDependencies_AreScopedCorrectly()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.lock"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "require": {
                "monolog/monolog": "3.5.0"
            },
            "require-dev": {
                "phpunit/phpunit": "10.5.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Name == "monolog/monolog" && p.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, p => p.Name == "phpunit/phpunit" && p.Scope == DependencyScope.Development);
    }

    [Fact]
    public async Task AnalyzeAsync_ComposerMetrics_ReflectPackageCounts()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "composer.lock"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "composer.json"), """
        {
            "require": {
                "monolog/monolog": "3.5.0",
                "guzzlehttp/guzzle": "7.8.0"
            }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Equal("1", inventory.Metrics["dependency.manifest.composer.count"]);
        Assert.Equal("2", inventory.Metrics["dependency.package.composer.count"]);
    }

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}

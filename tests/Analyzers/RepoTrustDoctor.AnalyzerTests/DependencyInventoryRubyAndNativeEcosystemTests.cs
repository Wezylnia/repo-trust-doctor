using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryRubyAndNativeEcosystemTests
{
    [Fact]
    public async Task AnalyzeAsync_GemfileWithoutLockfile_ReportsDep034()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "~> 7.1"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP034");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Gemfile", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_GemfileWithLockfile_DoesNotReportDep034()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "7.1.3"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP034");
    }

    [Fact]
    public async Task AnalyzeAsync_GemfilePinnedVersions_AreRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "7.1.3"
        gem "pg", "1.5.3"

        group :development, :test do
          gem "rspec-rails", "6.1.0"
        end
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Ruby);
        Assert.Contains(inventory.Packages, p => p.Name == "rails" && p.IsVersionPinned && p.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, p => p.Name == "rspec-rails" && p.Scope == DependencyScope.Development);
    }

    [Fact]
    public async Task AnalyzeAsync_GemfileNonExactVersion_ReportsDep035()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "~> 7.1"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP035" && f.Message.Contains("rails", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_GemfileMissingVersion_ReportsDep035()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP035" && f.Message.Contains("rails", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_GemfilePrereleaseVersion_ReportsDep049()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "7.2.0.beta1"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP049" && f.Message.Contains("rails", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_GemfileGitSource_ReportsDep036()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "mygem", git: "https://github.com/example/mygem.git"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP036" && f.Message.Contains("mygem", StringComparison.Ordinal));
        var inventory = GetInventory(result);
        var pkg = Assert.Single(inventory.Packages, p => p.Name == "mygem");
        Assert.Equal("git", pkg.Metadata?["sourceKind"]);
    }

    [Fact]
    public async Task AnalyzeAsync_GemspecParsesDependencies()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "mygem.gemspec"), """
        Gem::Specification.new do |spec|
          spec.name = "mygem"
          spec.add_dependency "rails", ">= 6.0"
          spec.add_development_dependency "rspec", "~> 3.0"
        end
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Name == "rails" && p.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, p => p.Name == "rspec" && p.Scope == DependencyScope.Development);
    }

    [Fact]
    public async Task AnalyzeAsync_RubyMetrics_ReflectPackageCounts()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Gemfile"), """
        source "https://rubygems.org"
        gem "rails", "7.1.3"
        gem "pg", "1.5.3"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Equal("1", inventory.Metrics["dependency.manifest.ruby.count"]);
        Assert.Equal("2", inventory.Metrics["dependency.package.ruby.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_PubspecWithoutLockfile_ReportsDep037()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.yaml"), """
        name: myapp
        dependencies:
          http: ^1.0.0
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP037");
    }

    [Fact]
    public async Task AnalyzeAsync_PubspecWithLockfile_DoesNotReportDep037()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.yaml"), "name: myapp");
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.lock"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP037");
    }

    [Fact]
    public async Task AnalyzeAsync_PubspecInSubdirectoryRequiresSiblingLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.lock"), "");
        var appDirectory = Path.Combine(fixture.Path, "apps", "mobile");
        Directory.CreateDirectory(appDirectory);
        File.WriteAllText(Path.Combine(appDirectory, "pubspec.yaml"), """
        name: mobile
        dependencies:
          http: 1.2.0
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP037" && f.Evidence[0].FilePath == "apps/mobile/pubspec.yaml");
    }

    [Fact]
    public async Task AnalyzeAsync_PubspecDependencies_AreRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "pubspec.yaml"), """
        name: myapp
        dependencies:
          http: 1.2.0
        dev_dependencies:
          test: 1.24.0
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Pub);
        Assert.NotEmpty(inventory.Packages);
    }

    [Fact]
    public async Task AnalyzeAsync_MixExsWithoutLockfile_ReportsDep040()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "mix.exs"), """
        defp deps do
          [{:phoenix, "~> 1.7"}]
        end
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP040");
    }

    [Fact]
    public async Task AnalyzeAsync_MixExsWithLockfile_DoesNotReportDep040()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "mix.exs"), "defp deps do [] end");
        File.WriteAllText(Path.Combine(fixture.Path, "mix.lock"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP040");
    }

    [Fact]
    public async Task AnalyzeAsync_MixExsDependencies_AreRecorded()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "mix.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "mix.exs"), """
        defp deps do
          [{:phoenix, "1.7.10"},
           {:ecto_sql, "~> 3.11"}]
        end
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Hex && p.Name == "phoenix");
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP041" && f.Message.Contains("ecto_sql", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_PackageSwiftWithoutResolved_ReportsDep043()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Package.swift"), """
        let package = Package(
            dependencies: [
                .package(url: "https://github.com/example/lib", from: "1.0.0")
            ]
        )
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP043");
    }

    [Fact]
    public async Task AnalyzeAsync_PackageSwiftBranchDependency_ReportsDep044()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Package.resolved"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Package.swift"), """
        let package = Package(
            dependencies: [
                .package(url: "https://github.com/example/lib", branch: "main")
            ]
        )
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP044");
    }

    [Fact]
    public async Task AnalyzeAsync_Conanfile_IsDetected()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "conanfile.txt"), """
        [requires]
        boost/1.83.0
        openssl/3.2.0
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Cpp);
        Assert.Contains(inventory.Packages, p => p.Name == "boost");
    }

    [Fact]
    public async Task AnalyzeAsync_VcpkgJson_IsParsed()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "vcpkg.json"), """
        {
            "dependencies": [
                {"name": "fmt", "version>=": "10.0.0"}
            ]
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cpp && p.Name == "fmt");
    }

    [Fact]
    public async Task AnalyzeAsync_VcpkgJsonStringDependencies_AreParsed()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "vcpkg.json"), """
        {
            "dependencies": [
                "fmt",
                {"name": "openssl", "version-string": "3.2.0"}
            ]
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Warnings ?? []);
        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cpp && p.Name == "fmt");
        Assert.Contains(inventory.Packages, p => p.Ecosystem == DependencyEcosystem.Cpp && p.Name == "openssl" && p.Version == "3.2.0");
    }

    [Fact]
    public async Task AnalyzeAsync_CmakeLists_FindPackage_IsDetected()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "CMakeLists.txt"), """
        cmake_minimum_required(VERSION 3.20)
        project(MyApp)
        find_package(Boost REQUIRED)
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Manifests, m => m.Ecosystem == DependencyEcosystem.Cpp && m.Kind == "CMakeLists.txt");
    }



    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}
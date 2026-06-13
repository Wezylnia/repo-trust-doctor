using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReturnsCompletedWithNoFindings_ForEmptyRepository()
    {
        using var fixture = TemporaryRepository.Create();

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmManifestWithoutLockfile_ReportsDep001()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP001");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("package.json", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_EmitsDependencyInventoryArtifact()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "left-pad": "1.3.0"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        var inventory = Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
        Assert.Single(inventory.Manifests, manifest => manifest.Ecosystem == DependencyEcosystem.Npm);
        Assert.Single(inventory.Lockfiles, lockfile => lockfile.Ecosystem == DependencyEcosystem.Npm);
        var package = Assert.Single(inventory.Packages);
        Assert.Equal("left-pad", package.Name);
        Assert.Equal("1.3.0", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Theory]
    [InlineData("package-lock.json")]
    [InlineData("pnpm-lock.yaml")]
    [InlineData("yarn.lock")]
    public async Task AnalyzeAsync_NpmManifestWithLockfile_DoesNotReportDep001(string lockfileName)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, lockfileName), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmWorkspaceManifestUsesRootLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), "");
        var packageDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app"));
        File.WriteAllText(Path.Combine(packageDirectory.FullName, "package.json"), """
        {
          "dependencies": {
            "react": "^19.0.0",
            "workspace-lib": "workspace:*"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-DEP001" or "TRUST-DEP006" or "TRUST-DEP012");
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, package => package.Name == "react");
        Assert.Equal("pnpm-lock.yaml", package.LockfilePath);
        Assert.Contains(inventory.Packages, package => package.Name == "workspace-lib" && package.Metadata?["sourceKind"] == "workspace");
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetProjectWithoutLockfile_ReportsDep002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "MyProject.csproj"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP002");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.Medium, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("MyProject.csproj", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetProjectWithLockfile_DoesNotReportDep002()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "MyProject.csproj"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetPackageReferences_AreRecordedAndRiskyVersionsReport()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "MyProject.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
            <PackageReference Include="Floating.Package" Version="1.*" />
            <PackageReference Include="Preview.Package">
              <Version>2.0.0-beta.1</Version>
            </PackageReference>
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Ecosystem == DependencyEcosystem.NuGet && package.Name == "Newtonsoft.Json" && package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP004" && finding.Message.Contains("Floating.Package", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP005" && finding.Message.Contains("Preview.Package", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetCentralPackageManagement_ResolvesVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Directory.Packages.props"), """
        <Project>
          <ItemGroup>
            <PackageVersion Include="xunit" Version="2.9.3" />
          </ItemGroup>
        </Project>
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Tests.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="xunit" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var package = Assert.Single(GetInventory(result).Packages, package => package.Name == "xunit");
        Assert.Equal("2.9.3", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetCentralPackageManagement_ResolvesMsBuildPropertyVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Versions.props"), """
        <Project>
          <PropertyGroup>
            <XunitVersion>2.9.3</XunitVersion>
          </PropertyGroup>
        </Project>
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Directory.Packages.props"), """
        <Project>
          <ItemGroup>
            <PackageVersion Include="xunit" Version="$(XunitVersion)" />
          </ItemGroup>
        </Project>
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Tests.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="xunit" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var package = Assert.Single(GetInventory(result).Packages, package => package.Name == "xunit");
        Assert.Equal("2.9.3", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetMsBuildPropertyExpansion_IsBounded()
    {
        using var fixture = TemporaryRepository.Create();
        var longValue = new string('1', 512);
        var expandingValue = string.Concat(Enumerable.Repeat("$(LongVersion)", 8));
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Versions.props"), $"""
        <Project>
          <PropertyGroup>
            <SafeVersion>2.9.3</SafeVersion>
            <LongVersion>{longValue}</LongVersion>
            <ExplosiveVersion>{expandingValue}</ExplosiveVersion>
          </PropertyGroup>
        </Project>
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Directory.Packages.props"), """
        <Project>
          <ItemGroup>
            <PackageVersion Include="Safe.Package" Version="$(SafeVersion)" />
            <PackageVersion Include="Generated.Package" Version="$(ExplosiveVersion)" />
          </ItemGroup>
        </Project>
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Project.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Safe.Package" />
            <PackageReference Include="Generated.Package" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "Safe.Package" && package.Version == "2.9.3" && package.IsVersionPinned);
        Assert.Contains(inventory.Packages, package => package.Name == "Generated.Package" && package.Version == "$(ExplosiveVersion)" && !package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP004" && finding.Message.Contains("Generated.Package", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetDynamicPackageReferenceNames_AreNotRecordedAsPackages()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Template.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="@(PackageReference)" />
            <PackageReference Include="Real.Package" Version="1.2.3" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.DoesNotContain(inventory.Packages, package => package.Name.Contains("PackageReference", StringComparison.Ordinal));
        Assert.Contains(inventory.Packages, package => package.Name == "Real.Package");
        Assert.DoesNotContain(result.Findings, finding => finding.Message.Contains("@(PackageReference)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetUnresolvedMsBuildVersion_DoesNotReportFloatingVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "Project.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Generated.Package" Version="$(GeneratedPackageVersion)" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var package = Assert.Single(GetInventory(result).Packages, package => package.Name == "Generated.Package");
        Assert.False(package.IsVersionPinned);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetTestProjectReferences_AreDevelopmentScope()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "tests"));
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "tests", "Widget.Tests.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <IsTestProject>true</IsTestProject>
          </PropertyGroup>
          <ItemGroup>
            <PackageReference Include="xunit.v3" Version="3.2.2" />
          </ItemGroup>
        </Project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var package = Assert.Single(GetInventory(result).Packages, package => package.Name == "xunit.v3");
        Assert.Equal(DependencyScope.Development, package.Scope);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetConfigSources_AreRecordedWithCredentialRedaction()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "NuGet.config"), """
        <configuration>
          <packageSources>
            <add key="private" value="https://user:secret@example.test/nuget/index.json" />
          </packageSources>
        </configuration>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var source = Assert.Single(GetInventory(result).PackageSources);
        Assert.Equal("private", source.Name);
        Assert.Contains("***", source.Source);
        Assert.DoesNotContain("secret", source.Source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetConfigSources_ReportInsecureAndLocalOrigins()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "NuGet.config"), """
        <configuration>
          <packageSources>
            <add key="internal-http" value="http://packages.example.test/v3/index.json" />
            <add key="local-feed" value="packages" />
          </packageSources>
        </configuration>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.PackageSources, source => source.Name == "internal-http" && !source.IsSecureTransport);
        Assert.Contains(inventory.PackageSources, source => source.Name == "local-feed" && source.IsLocal);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP013" && finding.Message.Contains("internal-http", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP014" && finding.Message.Contains("local-feed", StringComparison.Ordinal));
        Assert.Equal("1", inventory.Metrics["dependency.source.insecure.count"]);
        Assert.Equal("1", inventory.Metrics["dependency.source.local.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmDependenciesAndInstallScripts_AreRecordedAndReported()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "packageManager": "npm@10.0.0",
          "engines": { "node": ">=20" },
          "dependencies": {
            "react": "^19.0.0",
            "stable": "1.0.0"
          },
          "devDependencies": {
            "preview": "2.0.0-beta.1"
          },
          "scripts": {
            "postinstall": "node setup.js"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Ecosystem == DependencyEcosystem.Npm && package.Name == "stable" && package.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Manifests, manifest => manifest.Metadata?["packageManager"] == "npm@10.0.0");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP006" && finding.Message.Contains("react", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP007" && finding.Message.Contains("preview", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP008");
    }

    [Fact]
    public async Task AnalyzeAsync_NpmRangeWithoutLockfile_ReportsDep006()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "react": "^19.0.0"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP006" && finding.Message.Contains("react", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_NpmPrereleaseInToolingManifest_IsRecordedWithoutFinding()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), "");
        var toolingDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "build", "vite"));
        File.WriteAllText(Path.Combine(toolingDirectory.FullName, "package.json"), """
        {
          "dependencies": {
            "preview-tool": "1.0.0-beta.1"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "preview-tool" && package.IsPrerelease);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP007");
    }

    [Fact]
    public async Task AnalyzeAsync_NpmDirectAndLocalSources_AreRecordedAndReported()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "remote-lib": "github:example/remote-lib#main",
            "local-lib": "file:../local-lib",
            "stable": "1.0.0"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "remote-lib" && package.Metadata?["sourceKind"] == "remote");
        Assert.Contains(inventory.Packages, package => package.Name == "local-lib" && package.Metadata?["sourceKind"] == "local");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP011" && finding.Message.Contains("remote-lib", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP012" && finding.Message.Contains("local-lib", StringComparison.Ordinal));
        Assert.Equal("1", inventory.Metrics["dependency.package.npm.remote-source.count"]);
        Assert.Equal("1", inventory.Metrics["dependency.package.npm.local-source.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmLocalSourcesInFixtures_AreRecordedWithoutFindings()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pnpm-lock.yaml"), "");
        var testDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "tool", "__tests__"));
        File.WriteAllText(Path.Combine(testDirectory.FullName, "package.json"), """
        {
          "dependencies": {
            "fixture-lib": "file:./fixtures/fixture-lib"
          }
        }
        """);
        var playgroundDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "playground", "demo"));
        File.WriteAllText(Path.Combine(playgroundDirectory.FullName, "package.json"), """
        {
          "dependencies": {
            "playground-lib": "link:../playground-lib"
          }
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "fixture-lib" && package.Metadata?["sourceKind"] == "local");
        Assert.Contains(inventory.Packages, package => package.Name == "playground-lib" && package.Metadata?["sourceKind"] == "local");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP012");
    }

    [Fact]
    public async Task AnalyzeAsync_PythonRequirementsWithoutLockfile_ReportsDep003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "requirements.txt"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP003");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.Medium, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("requirements.txt", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_PythonRequirements_AreParsedAndUnpinnedVersionsReport()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "uv.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "requirements.txt"), """
        requests==2.31.0
        flask>=3.0.0
        preview==1.0.0b1
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Ecosystem == DependencyEcosystem.Python && package.Name == "requests" && package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP009" && finding.Message.Contains("flask", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_PythonDocsRequirements_AreInventoriedWithoutProductionRiskFindings()
    {
        using var fixture = TemporaryRepository.Create();
        var docsDirectory = Directory.CreateDirectory(Path.Combine(fixture.Path, "docs"));
        File.WriteAllText(Path.Combine(docsDirectory.FullName, "requirements.txt"), """
        Sphinx==4.5.0
        sphinxcontrib-spelling
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Ecosystem == DependencyEcosystem.Python && package.Name == "Sphinx");
        Assert.Contains(inventory.Packages, package => package.Ecosystem == DependencyEcosystem.Python && package.Name == "sphinxcontrib-spelling");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-DEP003" or "TRUST-DEP009");
    }

    [Fact]
    public async Task AnalyzeAsync_PythonPyprojectAndPipfile_AreParsedConservatively()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "poetry.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [project]
        dependencies = [
          "requests==2.31.0",
          "flask>=3.0.0"
        ]
        [tool.poetry.dependencies]
        httpx = "0.27.0"
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile"), """
        [packages]
        fastapi = "0.110.0"
        [dev-packages]
        pytest = "8.0.0"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "requests");
        Assert.Contains(inventory.Packages, package => package.Name == "httpx");
        Assert.Contains(inventory.Packages, package => package.Name == "fastapi" && package.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, package => package.Name == "pytest" && package.Scope == DependencyScope.Development);
    }

    [Fact]
    public async Task AnalyzeAsync_PythonPyprojectClassifiers_AreNotParsedAsDependencies()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "uv.lock"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), """
        [project]
        classifiers = [
          "Intended Audience :: Developers",
          "Programming Language :: Python :: 3",
          "Topic :: Internet :: WWW/HTTP"
        ]
        dependencies = ["fastapi>=0.110.0"]
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "fastapi");
        Assert.DoesNotContain(inventory.Packages, package => package.Name is "Intended" or "Programming" or "Topic");
        Assert.DoesNotContain(result.Findings, finding => finding.Message.Contains("Intended", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_PythonPyprojectWithoutLockfile_ReportsDep003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP003");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("pyproject.toml", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_PythonPipfileWithoutLockfile_ReportsDep003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-DEP003");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("Pipfile", evidence.FilePath);
    }

    [Theory]
    [InlineData("poetry.lock")]
    [InlineData("uv.lock")]
    public async Task AnalyzeAsync_PythonPyprojectWithLockfile_DoesNotReportDep003(string lockfileName)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pyproject.toml"), "");
        File.WriteAllText(Path.Combine(fixture.Path, lockfileName), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_PythonPipfileWithLockfile_DoesNotReportDep003()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "Pipfile.lock"), "");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}


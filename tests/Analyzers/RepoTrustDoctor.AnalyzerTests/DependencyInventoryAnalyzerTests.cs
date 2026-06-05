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
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP006" && finding.Message.Contains("react", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP007" && finding.Message.Contains("preview", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP008");
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

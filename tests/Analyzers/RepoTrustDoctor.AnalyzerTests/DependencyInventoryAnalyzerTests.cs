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
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP006" && finding.Message.Contains("react", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP007" && finding.Message.Contains("preview", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP008");
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

    [Fact]
    public async Task AnalyzeAsync_MavenPom_ParsesDependenciesAndReportsRiskyVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <properties>
            <spring.boot.version>3.3.1</spring.boot.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-web</artifactId>
              <version>${spring.boot.version}</version>
            </dependency>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>floating</artifactId>
              <version>[1.0,2.0)</version>
            </dependency>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>preview</artifactId>
              <version>1.0.0-SNAPSHOT</version>
            </dependency>
          </dependencies>
        </project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package =>
            package.Ecosystem == DependencyEcosystem.Maven &&
            package.Name == "org.springframework.boot:spring-boot-starter-web" &&
            package.Version == "3.3.1" &&
            package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP018" && finding.Message.Contains("com.example:floating", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP019" && finding.Message.Contains("com.example:preview", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnalyzeAsync_GradleBuild_ParsesDependenciesAndReportsMissingWrapper()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "gradle.lockfile"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "build.gradle"), """
        dependencies {
          implementation 'org.springframework.boot:spring-boot-starter-actuator:3.3.+'
          testImplementation 'org.junit.jupiter:junit-jupiter:5.10.2'
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "org.springframework.boot:spring-boot-starter-actuator" && package.Scope == DependencyScope.Production);
        Assert.Contains(inventory.Packages, package => package.Name == "org.junit.jupiter:junit-jupiter" && package.Scope == DependencyScope.Development);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP018" && finding.Message.Contains("spring-boot-starter-actuator", StringComparison.Ordinal));
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP020");
    }

    [Fact]
    public async Task AnalyzeAsync_JavaManifestWithoutLockfile_ReportsDep017()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), "<project />");

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-DEP017");
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("pom.xml", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_SpringBootActuatorExposure_ReportsDep021()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src", "main", "resources"));
        File.WriteAllText(Path.Combine(fixture.Path, "src", "main", "resources", "application.properties"), """
        management.endpoints.web.exposure.include=*
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-DEP021");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("src/main/resources/application.properties", Assert.Single(finding.Evidence).FilePath);
    }

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
        serde = "1.0.210"
        tokio = { version = "1.41.0", features = ["full"] }
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
    public async Task AnalyzeAsync_CargoNonExactVersion_ReportsDep029()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Cargo.lock"), "");
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

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}

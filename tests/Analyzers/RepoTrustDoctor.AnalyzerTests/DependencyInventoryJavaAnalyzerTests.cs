using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class DependencyInventoryJavaAnalyzerTests
{
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
    public async Task AnalyzeAsync_GradleBuildWithDependencyManagement_DoesNotReportMissingManagedVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "gradle.lockfile"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "build.gradle"), """
        plugins {
          id 'org.springframework.boot' version '3.3.1'
          id 'io.spring.dependency-management' version '1.1.5'
        }

        dependencies {
          implementation 'org.springframework.boot:spring-boot-starter-actuator'
          implementation 'org.springframework:spring-core'
          implementation "org.apache.ant:ant:${antVersion}"
        }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        var inventory = GetInventory(result);
        Assert.Contains(inventory.Packages, package => package.Name == "org.springframework.boot:spring-boot-starter-actuator" && package.Metadata?["versionSource"] == "gradle-managed");
        Assert.Contains(inventory.Packages, package => package.Name == "org.apache.ant:ant" && package.Metadata?["versionSource"] == "gradle-property");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP018");
    }

    [Fact]
    public async Task AnalyzeAsync_MavenPomWithParent_DoesNotReportMissingManagedVersions()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <parent>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-parent</artifactId>
            <version>3.3.1</version>
          </parent>
          <dependencies>
            <dependency>
              <groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-web</artifactId>
            </dependency>
          </dependencies>
        </project>
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(GetInventory(result).Packages, package => package.Name == "org.springframework.boot:spring-boot-starter-web" && package.Metadata?["versionSource"] == "maven-managed");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP018");
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
    public async Task AnalyzeAsync_SpringBootActuatorExposure_InSmokeTestConfigDoesNotReportDep021()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Directory.CreateDirectory(Path.Combine(fixture.Path, "smoke-test", "spring-boot-smoke-test-actuator", "src", "main", "resources"));
        File.WriteAllText(Path.Combine(directory.FullName, "application.properties"), """
        management.endpoints.web.exposure.include=*
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP021");
    }

    // â”€â”€ DEP050: Gradle version catalog dynamic versions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    [Fact]
    public async Task AnalyzeAsync_GradleVersionCatalog_DynamicVersion_ReportsDEP050()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "libs.versions.toml"), """
        [versions]
        spring = "3.3.+"
        kotlin = "1.9.24"
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP050");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP051");
    }

    [Fact]
    public async Task AnalyzeAsync_GradleVersionCatalog_DynamicLibraryVersion_ReportsDEP050()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "libs.versions.toml"), """
        [libraries]
        spring-core = { module = "org.springframework:spring-core", version = "latest.release" }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP050");
    }

    [Fact]
    public async Task AnalyzeAsync_GradleVersionCatalog_DynamicPluginVersion_ReportsDEP051()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "libs.versions.toml"), """
        [plugins]
        spring-boot = { id = "org.springframework.boot", version = "3.3.+" }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-DEP051");
    }

    [Fact]
    public async Task AnalyzeAsync_GradleVersionCatalog_PinnedVersions_NoDEP050()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "libs.versions.toml"), """
        [versions]
        spring = "3.3.1"
        kotlin = "1.9.24"
        [libraries]
        spring-core = { module = "org.springframework:spring-core", version = "3.3.1" }
        [plugins]
        spring-boot = { id = "org.springframework.boot", version = "3.3.1" }
        """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP050");
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-DEP051");
    }

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}


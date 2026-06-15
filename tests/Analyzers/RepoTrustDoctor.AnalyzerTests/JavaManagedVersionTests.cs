using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class JavaManagedVersionTests
{
    [Fact]
    public async Task AnalyzeAsync_LocalMavenManagement_ResolvesMatchingDependency()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <properties>
            <jackson.version>2.17.2</jackson.version>
          </properties>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>${jackson.version}</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
            </dependency>
          </dependencies>
        </project>
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("2.17.2", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("maven-dependency-management", package.Metadata!["versionSource"]);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP018");
    }

    [Fact]
    public async Task AnalyzeAsync_UnrelatedMavenManagement_DoesNotSuppressMissingVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.example</groupId>
                <artifactId>managed</artifactId>
                <version>1.0.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>unmanaged</artifactId>
            </dependency>
          </dependencies>
        </project>
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-DEP018");
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal(Confidence.Medium, finding.Confidence);
        Assert.Equal("maven-management-unverified", package.Metadata!["versionSource"]);
        Assert.False(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_DynamicMavenManagedVersion_RemainsUnpinned()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.example</groupId>
                <artifactId>managed</artifactId>
                <version>[1.0,2.0)</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>managed</artifactId>
            </dependency>
          </dependencies>
        </project>
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages);

        Assert.Equal("[1.0,2.0)", package.Version);
        Assert.False(package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP018");
    }

    [Fact]
    public async Task AnalyzeAsync_ArbitraryMavenParent_DoesNotSuppressMissingVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "maven-dependency-lock.json"), "{}");
        File.WriteAllText(Path.Combine(fixture.Path, "pom.xml"), """
        <project>
          <parent>
            <groupId>com.example</groupId>
            <artifactId>company-parent</artifactId>
            <version>1.0.0</version>
          </parent>
          <dependencies>
            <dependency>
              <groupId>org.apache.commons</groupId>
              <artifactId>commons-lang3</artifactId>
            </dependency>
          </dependencies>
        </project>
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-DEP018");

        Assert.Equal(Confidence.Medium, finding.Confidence);
    }

    [Fact]
    public async Task AnalyzeAsync_UnrelatedGradlePlatform_DoesNotSuppressMissingVersion()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "gradle.lockfile"), "");
        File.WriteAllText(Path.Combine(fixture.Path, "build.gradle"), """
        dependencies {
          implementation platform('com.example:company-bom:1.0.0')
          implementation 'org.apache.commons:commons-lang3'
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-DEP018");
        var package = Assert.Single(
            GetInventory(result).Packages,
            item => item.Name == "org.apache.commons:commons-lang3");

        Assert.Equal(Confidence.Medium, finding.Confidence);
        Assert.Equal("gradle-management-unverified", package.Metadata!["versionSource"]);
        Assert.False(package.IsVersionPinned);
    }

    private static Task<AnalyzerResult> AnalyzeAsync(string path) =>
        new DependencyInventoryAnalyzer().AnalyzeAsync(
            new AnalysisContext(path, path, AnalysisDepth.Standard),
            CancellationToken.None);

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result) =>
        Assert.IsType<DependencyInventoryArtifact>(
            Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey).Value);
}

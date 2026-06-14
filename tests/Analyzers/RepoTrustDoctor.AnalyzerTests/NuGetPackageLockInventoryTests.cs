using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class NuGetPackageLockInventoryTests
{
    [Fact]
    public async Task AnalyzeAsync_RangeResolvesConsistentDirectVersionAcrossTargets()
    {
        using var fixture = TemporaryRepository.Create();
        WriteProject(fixture.Path, "Project.csproj", "Shared.Package", "[2.0.0,3.0.0)");
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Shared.Package": {
                "type": "Direct",
                "requested": "[2.0.0, 3.0.0)",
                "resolved": "2.4.1"
              }
            },
            "net9.0": {
              "Shared.Package": {
                "type": "Direct",
                "requested": "[2.0.0, 3.0.0)",
                "resolved": "2.4.1"
              }
            }
          }
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var inventory = GetInventory(result);
        var package = Assert.Single(inventory.Packages, item => item.Name == "Shared.Package");

        Assert.Equal("2.4.1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("[2.0.0,3.0.0)", package.Metadata?["requestedVersion"]);
        Assert.Equal("packages.lock.json", package.Metadata?["versionSource"]);
        Assert.Equal("packages.lock.json", package.LockfilePath);
        Assert.Equal("1", inventory.Metrics["dependency.package.lock-resolved.count"]);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_DifferentResolvedVersionsAcrossTargetsRemainAmbiguous()
    {
        using var fixture = TemporaryRepository.Create();
        WriteProject(fixture.Path, "Project.csproj", "Target.Package", "[1.0.0,3.0.0)");
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Target.Package": {
                "type": "Direct",
                "resolved": "1.8.0"
              }
            },
            "net9.0": {
              "Target.Package": {
                "type": "Direct",
                "resolved": "2.1.0"
              }
            }
          }
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "Target.Package");

        Assert.Equal("[1.0.0,3.0.0)", package.Version);
        Assert.False(package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_RootLockfileDoesNotCoverNestedProject()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), """
        {
          "version": 1,
          "dependencies": {}
        }
        """);
        var nested = Directory.CreateDirectory(Path.Combine(fixture.Path, "src", "Nested"));
        WriteProject(nested.FullName, "Nested.csproj", "Nested.Package", "1.2.3");

        var result = await AnalyzeAsync(fixture.Path);
        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-DEP002");

        Assert.Contains(finding.Evidence, evidence => evidence.FilePath == "src/Nested/Nested.csproj");
        Assert.Null(Assert.Single(GetInventory(result).Packages).LockfilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_ProjectWithoutPackageReferencesDoesNotRequireLockfile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Project.csproj"), """
        <Project Sdk="Microsoft.NET.Sdk" />
        """);

        var result = await AnalyzeAsync(fixture.Path);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-DEP002");
    }

    [Fact]
    public async Task AnalyzeAsync_TransitiveLockEntryDoesNotReplaceDirectRequest()
    {
        using var fixture = TemporaryRepository.Create();
        WriteProject(fixture.Path, "Project.csproj", "Transitive.Package", "1.*");
        File.WriteAllText(Path.Combine(fixture.Path, "packages.lock.json"), """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Transitive.Package": {
                "type": "Transitive",
                "resolved": "1.9.4"
              }
            }
          }
        }
        """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "Transitive.Package");

        Assert.Equal("1.*", package.Version);
        Assert.False(package.IsVersionPinned);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-DEP004");
    }

    [Fact]
    public async Task AnalyzeAsync_NuGetLockfileCanExceedGeneralTextFileLimit()
    {
        using var fixture = TemporaryRepository.Create();
        WriteProject(fixture.Path, "Project.csproj", "Large.Lock.Package", "[5.0.0,6.0.0)");
        File.WriteAllText(
            Path.Combine(fixture.Path, "packages.lock.json"),
            $$"""
            {
              "version": 1,
              {{new string(' ', 600_000)}}
              "dependencies": {
                "net8.0": {
                  "Large.Lock.Package": {
                    "type": "Direct",
                    "resolved": "5.4.2"
                  }
                }
              }
            }
            """);

        var result = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "Large.Lock.Package");

        Assert.Equal("5.4.2", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Warnings ?? [], warning => warning.Contains("too large", StringComparison.OrdinalIgnoreCase));
    }

    private static void WriteProject(
        string directory,
        string fileName,
        string packageName,
        string version)
    {
        File.WriteAllText(Path.Combine(directory, fileName), $"""
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="{packageName}" Version="{version}" />
          </ItemGroup>
        </Project>
        """);
    }

    private static async Task<AnalyzerResult> AnalyzeAsync(string repositoryPath)
    {
        var analyzer = new DependencyInventoryAnalyzer();
        return await analyzer.AnalyzeAsync(
            new AnalysisContext(repositoryPath, repositoryPath, AnalysisDepth.Standard),
            CancellationToken.None);
    }

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}

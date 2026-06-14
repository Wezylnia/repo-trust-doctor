using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyInventory;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class NpmPackageLockInventoryTests
{
    [Fact]
    public async Task AnalyzeAsync_NpmRangeResolvesExactVersionFromPackageLock()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "react": "^19.0.0"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), """
        {
          "lockfileVersion": 3,
          "packages": {
            "": {
              "dependencies": {
                "react": "^19.0.0"
              }
            },
            "node_modules/react": {
              "version": "19.1.1"
            }
          }
        }
        """);

        var inventory = await AnalyzeAsync(fixture.Path);
        var package = Assert.Single(inventory.Packages, item => item.Name == "react");

        Assert.Equal("19.1.1", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.Equal("^19.0.0", package.Metadata?["requestedVersion"]);
        Assert.Equal("package-lock", package.Metadata?["versionSource"]);
        Assert.Equal("1", inventory.Metrics["dependency.package.lock-resolved.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmRangeResolvesFromPackageLockV1()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "legacy-package": "~4.1.0"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), """
        {
          "lockfileVersion": 1,
          "dependencies": {
            "legacy-package": {
              "version": "4.1.7"
            }
          }
        }
        """);

        var package = Assert.Single((await AnalyzeAsync(fixture.Path)).Packages, item => item.Name == "legacy-package");

        Assert.Equal("4.1.7", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmPackageLockCanExceedGeneralTextFileLimit()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "large-lock-package": "^5.0.0"
          }
        }
        """);
        File.WriteAllText(
            Path.Combine(fixture.Path, "package-lock.json"),
            $$"""
            {
              "lockfileVersion": 3,
              {{new string(' ', 600_000)}}
              "packages": {
                "node_modules/large-lock-package": {
                  "version": "5.3.2"
                }
              }
            }
            """);

        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Standard),
            CancellationToken.None);
        var package = Assert.Single(GetInventory(result).Packages, item => item.Name == "large-lock-package");

        Assert.Equal("5.3.2", package.Version);
        Assert.True(package.IsVersionPinned);
        Assert.DoesNotContain(result.Warnings ?? [], warning => warning.Contains("too large", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnalyzeAsync_NpmWorkspaceUsesWorkspaceSpecificPackageLockResolution()
    {
        using var fixture = TemporaryRepository.Create();
        var workspace = Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app"));
        File.WriteAllText(Path.Combine(workspace.FullName, "package.json"), """
        {
          "dependencies": {
            "shared-package": "^2.0.0"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), """
        {
          "lockfileVersion": 3,
          "packages": {
            "packages/app/node_modules/shared-package": {
              "version": "2.4.0"
            },
            "node_modules/shared-package": {
              "version": "1.9.0"
            }
          }
        }
        """);

        var package = Assert.Single((await AnalyzeAsync(fixture.Path)).Packages, item => item.Name == "shared-package");

        Assert.Equal("2.4.0", package.Version);
        Assert.True(package.IsVersionPinned);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmExactPrereleaseVersionIsPinned()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "preview-package": "2.0.0-beta.1"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), "{}");

        var package = Assert.Single((await AnalyzeAsync(fixture.Path)).Packages, item => item.Name == "preview-package");

        Assert.True(package.IsVersionPinned);
        Assert.True(package.IsPrerelease);
    }

    [Fact]
    public async Task AnalyzeAsync_NpmAliasIsNotResolvedAsAliasedPackageName()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "package.json"), """
        {
          "dependencies": {
            "compat-package": "npm:real-package@^3.0.0"
          }
        }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "package-lock.json"), """
        {
          "lockfileVersion": 3,
          "packages": {
            "node_modules/compat-package": {
              "name": "real-package",
              "version": "3.2.1"
            }
          }
        }
        """);

        var package = Assert.Single((await AnalyzeAsync(fixture.Path)).Packages, item => item.Name == "compat-package");

        Assert.Equal("npm:real-package@^3.0.0", package.Version);
        Assert.False(package.IsVersionPinned);
        Assert.Equal("alias", package.Metadata?["sourceKind"]);
    }

    private static async Task<DependencyInventoryArtifact> AnalyzeAsync(string repositoryPath)
    {
        var analyzer = new DependencyInventoryAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(repositoryPath, repositoryPath, AnalysisDepth.Standard),
            CancellationToken.None);
        return GetInventory(result);
    }

    private static DependencyInventoryArtifact GetInventory(AnalyzerResult result)
    {
        var artifact = Assert.Single(result.Artifacts!, artifact => artifact.Key == DependencyInventoryArtifact.ArtifactKey);
        return Assert.IsType<DependencyInventoryArtifact>(artifact.Value);
    }
}

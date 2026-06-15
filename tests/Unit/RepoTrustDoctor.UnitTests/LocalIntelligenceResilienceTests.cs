using Microsoft.Data.Sqlite;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.UnitTests;

public sealed class LocalIntelligenceResilienceTests
{
    [Fact]
    public async Task QueryBatchAsync_UsesOnlineFallbackWhenDatabaseIsCorrupt()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await File.WriteAllTextAsync(
            options.DatabasePath,
            "not a sqlite database",
            TestContext.Current.CancellationToken);
        var fallback = new StubOsvClient();
        var client = new LocalOsvAdvisoryClient(
            new SqliteOsvAdvisoryStore(new LocalIntelligenceDatabase(options)),
            fallback);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0")],
            TestContext.Current.CancellationToken);

        Assert.True(result.QuerySucceeded);
        Assert.Equal(1, result.OnlinePackageCount);
        Assert.Equal("ONLINE-1", Assert.Single(Assert.Single(result.Packages).Advisories).Id);
        Assert.Contains(
            result.Warnings,
            warning => warning.Contains("local OSV", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task QueryBatchAsync_UsesOnlineFallbackWhenDatabaseSchemaIsNewer()
    {
        using var fixture = TemporaryDirectory.Create();
        var options = CreateOptions(fixture.Path);
        await using (var connection = new SqliteConnection(
                         $"Data Source={options.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE local_schema (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                INSERT INTO local_schema(key, value)
                VALUES ('schema_version', '99');
                """;
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var fallback = new StubOsvClient();
        var client = new LocalOsvAdvisoryClient(
            new SqliteOsvAdvisoryStore(new LocalIntelligenceDatabase(options)),
            fallback);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0")],
            TestContext.Current.CancellationToken);

        Assert.True(result.QuerySucceeded);
        Assert.Equal(1, result.OnlinePackageCount);
        Assert.Contains(
            result.Warnings,
            warning => warning.Contains("local OSV", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task QueryBatchAsync_CanonicalizesPyPiPackageNames()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "PyPI", """
            {
              "id": "PYSEC-normalized",
              "summary": "normalized name",
              "affected": [
                {
                  "package": {
                    "ecosystem": "PyPI",
                    "name": "zope-interface"
                  },
                  "versions": ["6.0"]
                }
              ]
            }
            """);
        var client = new LocalOsvAdvisoryClient(store, null);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Python, "zope_interface", "6.0")],
            TestContext.Current.CancellationToken);

        Assert.Equal(
            "PYSEC-normalized",
            Assert.Single(Assert.Single(result.Packages).Advisories).Id);
    }

    [Theory]
    [InlineData(DependencyEcosystem.Go, "Go", "github.com/Acme/Module", "github.com/acme/module")]
    [InlineData(DependencyEcosystem.Maven, "Maven", "Com.Acme:Library", "com.acme:library")]
    public async Task QueryBatchAsync_DoesNotIgnoreCaseForCaseSensitiveEcosystems(
        DependencyEcosystem dependencyEcosystem,
        string osvEcosystem,
        string advisoryPackage,
        string queriedPackage)
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, osvEcosystem, $$"""
            {
              "id": "CASE-1",
              "summary": "case-sensitive package",
              "affected": [
                {
                  "package": {
                    "ecosystem": "{{osvEcosystem}}",
                    "name": "{{advisoryPackage}}"
                  },
                  "versions": ["1.0.0"]
                }
              ]
            }
            """);
        var client = new LocalOsvAdvisoryClient(store, null);

        var result = await client.QueryBatchAsync(
            [CreatePackage(dependencyEcosystem, queriedPackage, "1.0.0")],
            TestContext.Current.CancellationToken);

        Assert.Empty(Assert.Single(result.Packages).Advisories);
    }

    [Fact]
    public async Task QueryBatchAsync_FallsBackForInvalidSemanticVersion()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "npm", """
            {
              "id": "GHSA-semver",
              "summary": "semver range",
              "affected": [
                {
                  "package": {
                    "ecosystem": "npm",
                    "name": "example"
                  },
                  "ranges": [
                    {
                      "type": "SEMVER",
                      "events": [
                        { "introduced": "1.0.0" },
                        { "fixed": "2.0.0" }
                      ]
                    }
                  ]
                }
              ]
            }
            """);
        var fallback = new StubOsvClient();
        var client = new LocalOsvAdvisoryClient(store, fallback);

        await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "example", "01.5.0")],
            TestContext.Current.CancellationToken);

        Assert.Equal(1, fallback.BatchRequestCount);
    }

    [Fact]
    public async Task QueryBatchAsync_PreservesCertainMatchesWhenAnotherRangeIsInconclusive()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "Go", ExplicitAndInconclusiveAdvisories());

        var result = await new LocalOsvAdvisoryClient(store, null).QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Go, "github.com/acme/tool", "1.0.0")],
            TestContext.Current.CancellationToken);

        Assert.False(result.QuerySucceeded);
        Assert.Equal(
            "GO-EXPLICIT",
            Assert.Single(Assert.Single(result.Packages).Advisories).Id);
        Assert.Contains(
            result.Warnings,
            warning => warning.Contains("inconclusive", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ImportFullArchiveAsync_CountsOnlyIndexedEcosystemRecords()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await using var archive = OsvTestArchive.Create("""
            [
              {
                "id": "NPM-1",
                "affected": [
                  {
                    "package": {
                      "ecosystem": "npm",
                      "name": "left-pad"
                    },
                    "versions": ["1.0.0"]
                  }
                ]
              },
              {
                "id": "OTHER-1",
                "affected": [
                  {
                    "package": {
                      "ecosystem": "Maven",
                      "name": "com.acme:library"
                    },
                    "versions": ["1.0.0"]
                  }
                ]
              }
            ]
            """);

        var result = await new OsvDumpImporter(store).ImportFullArchiveAsync(
            "npm",
            archive,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);

        Assert.Equal(1, result.AdvisoryCount);
        Assert.Equal(1, result.PackageMappingCount);
    }

    private static LocalIntelligenceOptions CreateOptions(string directory) =>
        new()
        {
            DatabasePath = Path.Combine(directory, "intelligence.db"),
            ConnectionPoolingEnabled = false
        };

    private static SqliteOsvAdvisoryStore CreateStore(string directory) =>
        new(new LocalIntelligenceDatabase(CreateOptions(directory)));

    private static async Task ImportAsync(
        SqliteOsvAdvisoryStore store,
        string ecosystem,
        string advisoryJson)
    {
        await using var archive = OsvTestArchive.Create(advisoryJson);
        await new OsvDumpImporter(store).ImportFullArchiveAsync(
            ecosystem,
            archive,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
    }

    private static DependencyPackageInfo CreatePackage(
        DependencyEcosystem ecosystem,
        string name,
        string version) =>
        new(
            ecosystem,
            name,
            version,
            DependencyScope.Production,
            "manifest",
            "lockfile",
            true,
            true,
            false);

    private sealed class StubOsvClient : IOsvAdvisoryClient
    {
        public int BatchRequestCount { get; private set; }

        public Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
            DependencyPackageInfo package,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<VulnerabilityAdvisory>>([CreateAdvisory()]);

        public Task<OsvBatchQueryResult> QueryBatchAsync(
            IReadOnlyList<DependencyPackageInfo> packages,
            CancellationToken cancellationToken)
        {
            BatchRequestCount++;
            return Task.FromResult(new OsvBatchQueryResult(
                packages.Select(package =>
                    new OsvPackageQueryResult(package, [CreateAdvisory()])).ToArray(),
                true,
                [])
            {
                OnlinePackageCount = packages.Count
            });
        }

        private static VulnerabilityAdvisory CreateAdvisory() =>
            new("ONLINE-1", [], "online fallback", Severity.High, [], null, null);
    }

    private static string ExplicitAndInconclusiveAdvisories() => """
        [
          {
            "id": "GO-INCONCLUSIVE",
            "affected": [
              {
                "package": {
                  "ecosystem": "Go",
                  "name": "github.com/acme/tool"
                },
                "ranges": [
                  {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}]
                  }
                ]
              }
            ]
          },
          {
            "id": "GO-EXPLICIT",
            "affected": [
              {
                "package": {
                  "ecosystem": "Go",
                  "name": "github.com/acme/tool"
                },
                "versions": ["1.0.0"]
              }
            ]
          }
        ]
        """;
}

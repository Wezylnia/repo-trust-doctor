using System.IO.Compression;
using System.Text;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.LocalData;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.UnitTests;

public sealed class LocalOsvAdvisoryTests
{
    [Fact]
    public async Task QueryBatchAsync_MatchesSemverRangeFromImportedArchive()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "npm", """
        {
          "id": "GHSA-local",
          "summary": "local advisory",
          "affected": [
            {
              "package": { "ecosystem": "npm", "name": "left-pad" },
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
        var client = new LocalOsvAdvisoryClient(store, null);

        var vulnerable = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.5.0")],
            CancellationToken.None);
        var fixedResult = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "2.0.0")],
            CancellationToken.None);

        Assert.True(vulnerable.QuerySucceeded);
        Assert.Equal(1, vulnerable.LocalPackageCount);
        Assert.Equal(0, vulnerable.OnlinePackageCount);
        Assert.Equal("GHSA-local", Assert.Single(Assert.Single(vulnerable.Packages).Advisories).Id);
        Assert.Empty(Assert.Single(fixedResult.Packages).Advisories);
    }

    [Fact]
    public async Task QueryBatchAsync_MatchesExplicitNonSemverVersion()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "PyPI", """
        {
          "id": "PYSEC-local",
          "summary": "python advisory",
          "affected": [
            {
              "package": { "ecosystem": "PyPI", "name": "example" },
              "versions": ["1.0rc1"]
            }
          ]
        }
        """);
        var client = new LocalOsvAdvisoryClient(store, null);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Python, "example", "1.0rc1")],
            CancellationToken.None);

        Assert.True(result.QuerySucceeded);
        Assert.Equal("PYSEC-local", Assert.Single(Assert.Single(result.Packages).Advisories).Id);
    }

    [Fact]
    public async Task QueryBatchAsync_UsesOnlineFallbackForIndeterminateRange()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "PyPI", """
        {
          "id": "PYSEC-range",
          "summary": "python range advisory",
          "affected": [
            {
              "package": { "ecosystem": "PyPI", "name": "example" },
              "ranges": [
                {
                  "type": "ECOSYSTEM",
                  "events": [
                    { "introduced": "1.0rc1" },
                    { "fixed": "1.0.post1" }
                  ]
                }
              ]
            }
          ]
        }
        """);
        var fallback = new StubOsvClient();
        var client = new LocalOsvAdvisoryClient(store, fallback);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Python, "example", "1.0")],
            CancellationToken.None);

        Assert.True(result.QuerySucceeded);
        Assert.Equal(1, fallback.BatchRequestCount);
        Assert.Equal(0, result.LocalPackageCount);
        Assert.Equal(1, result.OnlinePackageCount);
        Assert.Equal("ONLINE-1", Assert.Single(Assert.Single(result.Packages).Advisories).Id);
        Assert.Contains(result.Warnings, warning => warning.Contains("inconclusive", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task QueryBatchAsync_UsesOnlineFallbackForEcosystemRangeEvenWhenNumeric()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "NuGet", """
        {
          "id": "GHSA-nuget-range",
          "summary": "NuGet ecosystem range",
          "affected": [
            {
              "package": { "ecosystem": "NuGet", "name": "Example.Package" },
              "ranges": [
                {
                  "type": "ECOSYSTEM",
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
            [CreatePackage(DependencyEcosystem.NuGet, "Example.Package", "1.5.0")],
            CancellationToken.None);

        Assert.Equal(1, fallback.BatchRequestCount);
    }

    [Fact]
    public void ParseModifiedIndex_AcceptsOfficialTimestampFirstFormat()
    {
        var result = OsvFeedUpdater.ParseModifiedIndex("""
        2026-06-14T08:01:45.295865599Z,MAL-2026-5759
        2026-06-14T08:01:43.834010403Z,MAL-2026-5729
        """);

        Assert.Equal(2, result.Count);
        Assert.Equal("MAL-2026-5759", result[0].AdvisoryId);
        Assert.Equal(2026, result[0].ModifiedAt.Year);
    }

    [Fact]
    public async Task ImportFullArchiveAsync_RejectsEmptyArchiveWithoutReplacingIndex()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "npm", AdvisoryWithExplicitVersion("GHSA-old", "old-package", "1.0.0"));
        await using var emptyArchive = CreateArchive(null);
        var importer = new OsvDumpImporter(store);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            importer.ImportFullArchiveAsync(
                "npm",
                emptyArchive,
                DateTimeOffset.UtcNow,
                CancellationToken.None));

        var result = await new LocalOsvAdvisoryClient(store, null).QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "old-package", "1.0.0")],
            CancellationToken.None);
        Assert.Equal("GHSA-old", Assert.Single(Assert.Single(result.Packages).Advisories).Id);
    }

    [Fact]
    public async Task ImportFullArchiveAsync_ReplacesPreviousEcosystemMappings()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        await ImportAsync(store, "npm", AdvisoryWithExplicitVersion("GHSA-old", "old-package", "1.0.0"));
        await ImportAsync(store, "npm", AdvisoryWithExplicitVersion("GHSA-new", "new-package", "2.0.0"));
        var client = new LocalOsvAdvisoryClient(store, null);

        var oldResult = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "old-package", "1.0.0")],
            CancellationToken.None);
        var newResult = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "new-package", "2.0.0")],
            CancellationToken.None);

        Assert.Empty(Assert.Single(oldResult.Packages).Advisories);
        Assert.Equal("GHSA-new", Assert.Single(Assert.Single(newResult.Packages).Advisories).Id);
    }

    [Fact]
    public async Task RefreshEcosystemAsync_ImportsOnlyModifiedAdvisories()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        var now = new DateTimeOffset(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);
        await ImportAsync(
            store,
            "npm",
            AdvisoryWithExplicitVersion("GHSA-old", "old-package", "1.0.0"),
            now.AddHours(-1));
        var source = new StubOsvFeedSource
        {
            ModifiedIndex = $"{now.AddMinutes(-30):O},GHSA-new",
            AdvisoryJson = AdvisoryWithExplicitVersion("GHSA-new", "new-package", "2.0.0")
        };
        var options = new LocalIntelligenceOptions
        {
            OsvEcosystems = ["npm"],
            FullOsvRefreshInterval = TimeSpan.FromDays(7)
        };
        var updater = new OsvFeedUpdater(
            options,
            store,
            new OsvDumpImporter(store),
            source,
            new FixedTimeProvider(now));

        var result = await updater.RefreshEcosystemAsync(
            "npm",
            TestContext.Current.CancellationToken);

        Assert.Equal("incremental", result.Mode);
        Assert.Equal(1, result.AdvisoryCount);
        Assert.Equal(0, source.FullArchiveRequestCount);
        Assert.Equal(1, source.AdvisoryRequestCount);
        var query = await new LocalOsvAdvisoryClient(store, null).QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "new-package", "2.0.0")],
            TestContext.Current.CancellationToken);
        Assert.Equal("GHSA-new", Assert.Single(Assert.Single(query.Packages).Advisories).Id);
    }

    [Fact]
    public async Task RefreshAsync_ContinuesAfterOneEcosystemFails()
    {
        using var fixture = TemporaryDirectory.Create();
        var store = CreateStore(fixture.Path);
        var source = new MultiEcosystemOsvFeedSource();
        var options = new LocalIntelligenceOptions
        {
            OsvEcosystems = ["npm", "NuGet"]
        };
        var updater = new OsvFeedUpdater(
            options,
            store,
            new OsvDumpImporter(store),
            source);

        var results = await updater.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, results.Count);
        Assert.False(results[0].Succeeded);
        Assert.True(results[1].Succeeded);
        var query = await new LocalOsvAdvisoryClient(store, null).QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.NuGet, "Example.Package", "1.0.0")],
            TestContext.Current.CancellationToken);
        Assert.Equal("GHSA-nuget", Assert.Single(Assert.Single(query.Packages).Advisories).Id);
    }

    private static SqliteOsvAdvisoryStore CreateStore(string directory)
    {
        var options = new LocalIntelligenceOptions
        {
            DatabasePath = Path.Combine(directory, "intelligence.db"),
            ConnectionPoolingEnabled = false
        };
        return new SqliteOsvAdvisoryStore(new LocalIntelligenceDatabase(options));
    }

    private static async Task ImportAsync(
        SqliteOsvAdvisoryStore store,
        string ecosystem,
        string advisoryJson,
        DateTimeOffset? importedAt = null)
    {
        await using var archive = CreateArchive(advisoryJson);
        await new OsvDumpImporter(store).ImportFullArchiveAsync(
            ecosystem,
            archive,
            importedAt ?? DateTimeOffset.UtcNow,
            CancellationToken.None);
    }

    private static MemoryStream CreateArchive(string? advisoryJson)
    {
        var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            if (advisoryJson is not null)
            {
                var entry = archive.CreateEntry("advisory.json");
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(advisoryJson);
            }
        }

        output.Position = 0;
        return output;
    }

    private static string AdvisoryWithExplicitVersion(
        string id,
        string packageName,
        string version) =>
        $$"""
        {
          "id": "{{id}}",
          "summary": "explicit version advisory",
          "affected": [
            {
              "package": { "ecosystem": "npm", "name": "{{packageName}}" },
              "versions": ["{{version}}"]
            }
          ]
        }
        """;

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
                []));
        }

        private static VulnerabilityAdvisory CreateAdvisory() =>
            new("ONLINE-1", [], "online fallback", Severity.High, [], null, null);
    }

    private sealed class StubOsvFeedSource : IOsvFeedSource
    {
        public string ModifiedIndex { get; init; } = string.Empty;

        public string AdvisoryJson { get; init; } = string.Empty;

        public int FullArchiveRequestCount { get; private set; }

        public int AdvisoryRequestCount { get; private set; }

        public Task<Stream> OpenFullArchiveAsync(
            string ecosystem,
            CancellationToken cancellationToken)
        {
            FullArchiveRequestCount++;
            return Task.FromResult<Stream>(CreateArchive(AdvisoryJson));
        }

        public Task<string> GetModifiedIndexAsync(
            string ecosystem,
            CancellationToken cancellationToken) =>
            Task.FromResult(ModifiedIndex);

        public Task<string> GetAdvisoryAsync(
            string ecosystem,
            string advisoryId,
            CancellationToken cancellationToken)
        {
            AdvisoryRequestCount++;
            return Task.FromResult(AdvisoryJson);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MultiEcosystemOsvFeedSource : IOsvFeedSource
    {
        public Task<Stream> OpenFullArchiveAsync(
            string ecosystem,
            CancellationToken cancellationToken)
        {
            if (ecosystem == "npm")
            {
                throw new HttpRequestException("simulated npm feed failure");
            }

            const string advisory = """
                {
                  "id": "GHSA-nuget",
                  "summary": "NuGet advisory",
                  "affected": [
                    {
                      "package": {
                        "ecosystem": "NuGet",
                        "name": "Example.Package"
                      },
                      "versions": ["1.0.0"]
                    }
                  ]
                }
                """;
            return Task.FromResult<Stream>(CreateArchive(advisory));
        }

        public Task<string> GetModifiedIndexAsync(
            string ecosystem,
            CancellationToken cancellationToken) =>
            Task.FromResult(string.Empty);

        public Task<string> GetAdvisoryAsync(
            string ecosystem,
            string advisoryId,
            CancellationToken cancellationToken) =>
            Task.FromResult(string.Empty);
    }
}

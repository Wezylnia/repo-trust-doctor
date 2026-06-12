using System.IO.Compression;
using System.Net;
using System.Text;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;
using RepoTrustDoctor.Infrastructure.SecurityFeeds;

namespace RepoTrustDoctor.UnitTests;

public sealed class PackageInfrastructureTests
{
    [Fact]
    public async Task SafeHttpLookup_AllowsAllowlistedHttpsHost()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            }));

        var result = await lookup.GetStringAsync(new Uri("https://registry.example.test/package"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("{}", result.Body);
    }

    [Fact]
    public async Task SafeHttpLookup_DecodesGzipResponses()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Gzip("{}"))
                };
                response.Content.Headers.ContentEncoding.Add("gzip");
                return response;
            }));

        var result = await lookup.GetStringAsync(new Uri("https://registry.example.test/package"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("{}", result.Body);
    }

    [Theory]
    [InlineData("http://registry.example.test/package")]
    [InlineData("https://user:pass@registry.example.test/package")]
    [InlineData("https://localhost/package")]
    [InlineData("https://127.0.0.1/package")]
    public async Task SafeHttpLookup_BlocksUnsafeUrls(string url)
    {
        var lookup = new SafeHttpLookup(["registry.example.test"], new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));

        var result = await lookup.GetStringAsync(new Uri(url), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.BlockedUrl, result.ErrorKind);
    }

    [Fact]
    public async Task SafeHttpLookup_BlocksOversizedResponses()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("0123456789")
            }),
            maxResponseBytes: 3);

        var result = await lookup.GetStringAsync(new Uri("https://registry.example.test/package"), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.TooLarge, result.ErrorKind);
    }

    [Fact]
    public async Task SafeHttpLookup_HandlesHttpRequestException()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => throw new HttpRequestException("Network error")));

        var result = await lookup.GetStringAsync(new Uri("https://registry.example.test/package"), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.TransportError, result.ErrorKind);
    }

    [Fact]
    public async Task SafeHttpLookup_ThrowsOnUserCancellation()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            lookup.GetStringAsync(new Uri("https://registry.example.test/package"), cts.Token));
    }

    [Fact]
    public void PackageLicenseNormalizer_ClassifiesCommonLicenses()
    {
        Assert.Equal(PackageLicenseFamily.Permissive, PackageLicenseNormalizer.Normalize("MIT").Family);
        Assert.Equal(PackageLicenseFamily.Permissive, PackageLicenseNormalizer.Normalize("Apache 2.0").Family);
        var agpl = PackageLicenseNormalizer.Normalize("AGPL-3.0-only");

        Assert.Equal(PackageLicenseFamily.Copyleft, agpl.Family);
        Assert.True(agpl.IsPolicySensitive);
        Assert.False(PackageLicenseNormalizer.Normalize("custom license text").IsKnown);
        Assert.False(PackageLicenseNormalizer.Normalize(new string('x', 200)).IsKnown);
    }

    [Fact]
    public void PackageMetadataParser_ParsesNpmFixture()
    {
        var package = CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0");
        var metadata = PackageMetadataParser.ParseNpm(package, """
        {
          "dist-tags": { "latest": "2.0.0" },
          "time": { "2.0.0": "2026-01-01T00:00:00.000Z" },
          "versions": {
            "2.0.0": {
              "version": "2.0.0",
              "license": "MIT",
              "repository": { "url": "git+https://github.com/example/left-pad.git" },
              "deprecated": "use something else"
            }
          }
        }
        """);

        Assert.NotNull(metadata);
        Assert.Equal("2.0.0", metadata!.LatestVersion);
        Assert.Equal("MIT", metadata.LicenseExpression);
        Assert.True(metadata.IsDeprecated);
        Assert.Contains("github.com", metadata.RepositoryUrl);
    }

    [Fact]
    public void PackageMetadataParser_ParsesMavenCentralFixture()
    {
        var package = CreatePackage(DependencyEcosystem.Maven, "org.springframework.boot:spring-boot-starter-web", "3.3.1");
        var metadata = PackageMetadataParser.ParseMavenCentral(package, """
        {
          "response": {
            "docs": [
              {
                "g": "org.springframework.boot",
                "a": "spring-boot-starter-web",
                "latestVersion": "3.5.0",
                "timestamp": 1760000000000
              }
            ]
          }
        }
        """);

        Assert.NotNull(metadata);
        Assert.Equal("3.5.0", metadata!.LatestVersion);
        Assert.Equal("search.maven.org", metadata.SourceRegistry);
        Assert.Equal(DependencyEcosystem.Maven, metadata.Ecosystem);
    }

    [Fact]
    public void OsvAdvisoryClient_ParsesAdvisoryFixture()
    {
        var advisories = OsvAdvisoryClient.Parse("""
        {
          "vulns": [
            {
              "id": "GHSA-test",
              "aliases": ["CVE-2026-0001"],
              "summary": "test advisory",
              "database_specific": { "severity": "CRITICAL" },
              "affected": [
                { "ranges": [ { "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ] } ] }
              ],
              "published": "2026-01-01T00:00:00Z"
            }
          ]
        }
        """);

        var advisory = Assert.Single(advisories);
        Assert.Equal("GHSA-test", advisory.Id);
        Assert.Equal(Severity.Critical, advisory.Severity);
        Assert.Contains("2.0.0", advisory.FixedVersions);
    }

    private static DependencyPackageInfo CreatePackage(DependencyEcosystem ecosystem, string name, string version) =>
        new(ecosystem, name, version, DependencyScope.Production, "manifest", null, true, true, false);

    private static byte[] Gzip(string value)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(value));
        }

        return output.ToArray();
    }

    private sealed class StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(handler(request));
    }
}

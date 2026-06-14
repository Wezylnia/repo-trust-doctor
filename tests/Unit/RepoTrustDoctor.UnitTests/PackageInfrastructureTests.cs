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
    public void PackageMetadataParser_ParsesNuGetLatestUsingSemanticVersionOrdering()
    {
        var package = CreatePackage(DependencyEcosystem.NuGet, "Example.Package", "9.0.0");
        var metadata = PackageMetadataParser.ParseNuGet(package, """
        {
          "items": [
            {
              "items": [
                {
                  "catalogEntry": {
                    "version": "9.0.0",
                    "published": "2025-01-01T00:00:00Z",
                    "licenseExpression": "MIT"
                  }
                },
                {
                  "catalogEntry": {
                    "version": "10.0.0-preview.1",
                    "published": "2025-02-01T00:00:00Z"
                  }
                },
                {
                  "catalogEntry": {
                    "version": "10.0.0",
                    "published": "2025-03-01T00:00:00Z"
                  }
                }
              ]
            }
          ]
        }
        """);

        Assert.NotNull(metadata);
        Assert.Equal("10.0.0", metadata!.LatestVersion);
        Assert.Equal(DateTimeOffset.Parse("2025-01-01T00:00:00Z"), metadata.PublishedAt);
        Assert.Equal("MIT", metadata.LicenseExpression);
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

    [Fact]
    public void OsvAdvisoryClient_DoesNotTreatCvssVersionAsCriticalSeverity()
    {
        var advisory = OsvAdvisoryClient.ParseAdvisory("""
        {
          "id": "GHSA-vector",
          "summary": "vector without a numeric base score",
          "severity": [
            { "type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P" }
          ]
        }
        """);

        Assert.Equal(Severity.Medium, advisory.Severity);
    }

    [Fact]
    public void OsvAdvisoryClient_ParsesCvssV3VectorSeverity()
    {
        var advisory = OsvAdvisoryClient.ParseAdvisory("""
        {
          "id": "GHSA-vector-critical",
          "summary": "critical vector",
          "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
          ]
        }
        """);

        Assert.Equal(Severity.Critical, advisory.Severity);
    }

    [Fact]
    public void OsvAdvisoryClient_RejectsTruncatedBatchResponses()
    {
        var exception = Assert.Throws<System.Text.Json.JsonException>(() =>
            OsvAdvisoryClient.ParseBatchAdvisoryIds(
                """{ "results": [ { "vulns": [] } ] }""",
                expectedResultCount: 2));

        Assert.Contains("1 results for 2 queries", exception.Message);
    }

    [Fact]
    public async Task OsvAdvisoryClient_BatchesQueriesAndUsesPackageSpecificFixedVersions()
    {
        var requestedPaths = new List<string>();
        var lookup = new SafeHttpLookup(
            ["api.osv.dev"],
            new StubHttpHandler(request =>
            {
                requestedPaths.Add($"{request.Method} {request.RequestUri!.AbsolutePath}");
                if (request.Method == HttpMethod.Post)
                {
                    var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                    Assert.Contains("\"left-pad\"", body);
                    Assert.Contains("\"NuGet\"", body);
                    return JsonResponse("""
                    {
                      "results": [
                        { "vulns": [ { "id": "GHSA-test", "modified": "2026-01-01T00:00:00Z" } ] },
                        { "vulns": [] }
                      ]
                    }
                    """);
                }

                return JsonResponse("""
                {
                  "id": "GHSA-test",
                  "summary": "test advisory",
                  "affected": [
                    {
                      "package": { "ecosystem": "npm", "name": "left-pad" },
                      "ecosystem_specific": { "severity": "HIGH" },
                      "ranges": [ { "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ] } ]
                    },
                    {
                      "package": { "ecosystem": "npm", "name": "other-package" },
                      "ranges": [ { "events": [ { "introduced": "0" }, { "fixed": "99.0.0" } ] } ]
                    }
                  ]
                }
                """);
            }));
        var client = new OsvAdvisoryClient(lookup);

        var result = await client.QueryBatchAsync(
            [
                CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0"),
                CreatePackage(DependencyEcosystem.NuGet, "Example.Package", "1.0.0")
            ],
            CancellationToken.None);

        Assert.True(result.QuerySucceeded);
        Assert.Equal(2, result.Packages.Count);
        var advisory = Assert.Single(result.Packages[0].Advisories);
        Assert.Equal(Severity.High, advisory.Severity);
        Assert.Equal(["2.0.0"], advisory.FixedVersions);
        Assert.Empty(result.Packages[1].Advisories);
        Assert.Contains("POST /v1/querybatch", requestedPaths);
        Assert.Contains("GET /v1/vulns/GHSA-test", requestedPaths);
    }

    [Fact]
    public async Task OsvAdvisoryClient_PreservesConfirmedMatchWhenDetailsFail()
    {
        var lookup = new SafeHttpLookup(
            ["api.osv.dev"],
            new StubHttpHandler(request =>
                request.Method == HttpMethod.Post
                    ? JsonResponse("""{ "results": [ { "vulns": [ { "id": "GHSA-test" } ] } ] }""")
                    : new HttpResponseMessage(HttpStatusCode.NotFound)));
        var client = new OsvAdvisoryClient(lookup);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0")],
            CancellationToken.None);

        var advisory = Assert.Single(Assert.Single(result.Packages).Advisories);
        Assert.Equal("GHSA-test", advisory.Id);
        Assert.Equal(Severity.Medium, advisory.Severity);
        Assert.Contains(result.Warnings, warning => warning.Contains("could not be loaded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task OsvAdvisoryClient_FollowsPerPackageBatchPagination()
    {
        var postCount = 0;
        var lookup = new SafeHttpLookup(
            ["api.osv.dev"],
            new StubHttpHandler(request =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    var id = request.RequestUri!.Segments[^1];
                    return JsonResponse($$"""
                    {
                      "id": "{{id}}",
                      "summary": "paginated advisory",
                      "database_specific": { "severity": "HIGH" }
                    }
                    """);
                }

                postCount++;
                var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                if (postCount == 1)
                {
                    Assert.DoesNotContain("page_token", body);
                    return JsonResponse("""
                    {
                      "results": [
                        {
                          "vulns": [ { "id": "GHSA-page-1" } ],
                          "next_page_token": "next-token"
                        }
                      ]
                    }
                    """);
                }

                Assert.Contains("\"page_token\":\"next-token\"", body);
                return JsonResponse("""
                {
                  "results": [
                    { "vulns": [ { "id": "GHSA-page-2" } ] }
                  ]
                }
                """);
            }));
        var client = new OsvAdvisoryClient(lookup);

        var result = await client.QueryBatchAsync(
            [CreatePackage(DependencyEcosystem.Npm, "left-pad", "1.0.0")],
            CancellationToken.None);

        Assert.True(result.QuerySucceeded);
        Assert.Equal(2, Assert.Single(result.Packages).Advisories.Count);
        Assert.Equal(2, postCount);
    }

    [Theory]
    [InlineData(DependencyEcosystem.Npm, true)]
    [InlineData(DependencyEcosystem.NuGet, true)]
    [InlineData(DependencyEcosystem.Python, true)]
    [InlineData(DependencyEcosystem.Maven, true)]
    [InlineData(DependencyEcosystem.Go, true)]
    [InlineData(DependencyEcosystem.Cargo, true)]
    [InlineData(DependencyEcosystem.Composer, true)]
    [InlineData(DependencyEcosystem.Ruby, true)]
    [InlineData(DependencyEcosystem.Pub, true)]
    [InlineData(DependencyEcosystem.Hex, true)]
    [InlineData(DependencyEcosystem.Swift, true)]
    [InlineData(DependencyEcosystem.Cpp, false)]
    public void OsvAdvisoryClient_ReportsSupportedEcosystems(
        DependencyEcosystem ecosystem,
        bool expected)
    {
        var client = new OsvAdvisoryClient(new SafeHttpLookup(["api.osv.dev"]));

        Assert.Equal(expected, client.SupportsEcosystem(ecosystem));
    }

    private static DependencyPackageInfo CreatePackage(DependencyEcosystem ecosystem, string name, string version) =>
        new(ecosystem, name, version, DependencyScope.Production, "manifest", null, true, true, false);

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

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

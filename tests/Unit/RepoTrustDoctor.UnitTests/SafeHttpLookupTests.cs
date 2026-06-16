using System.IO.Compression;
using System.Net;
using System.Text;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.UnitTests;

public sealed class SafeHttpLookupTests
{
    [Fact]
    public async Task GetStringAsync_AllowsAllowlistedHttpsHost()
    {
        var lookup = CreateLookup(HttpStatusCode.OK, "{}");

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("{}", result.Body);
    }

    [Fact]
    public async Task GetStringAsync_DecodesGzipResponses()
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

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("{}", result.Body);
    }

    [Fact]
    public async Task GetStringAsync_ClassifiesMalformedCompressedResponse()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent([0x01, 0x02, 0x03])
                };
                response.Content.Headers.ContentEncoding.Add("gzip");
                return response;
            }));

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.MalformedResponse, result.ErrorKind);
        Assert.Equal(
            PackageMetadataLookupStatus.InvalidResponse,
            PackageMetadataLookupResult.FromSafeLookupFailure(result).Status);
    }

    [Theory]
    [InlineData("http://registry.example.test/package")]
    [InlineData("https://user:pass@registry.example.test/package")]
    [InlineData("https://localhost/package")]
    [InlineData("https://127.0.0.1/package")]
    public async Task GetStringAsync_BlocksUnsafeUrls(string url)
    {
        var lookup = CreateLookup(HttpStatusCode.OK);

        var result = await lookup.GetStringAsync(new Uri(url), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.BlockedUrl, result.ErrorKind);
    }

    [Fact]
    public async Task GetStringAsync_BlocksOversizedResponses()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("0123456789")
            }),
            maxResponseBytes: 3);

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.TooLarge, result.ErrorKind);
    }

    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout, SafeLookupErrorKind.Timeout, PackageMetadataLookupStatus.TransientFailure)]
    [InlineData(HttpStatusCode.TooManyRequests, SafeLookupErrorKind.RateLimited, PackageMetadataLookupStatus.TransientFailure)]
    [InlineData(HttpStatusCode.ServiceUnavailable, SafeLookupErrorKind.ServerError, PackageMetadataLookupStatus.TransientFailure)]
    [InlineData(HttpStatusCode.BadRequest, SafeLookupErrorKind.RejectedRequest, PackageMetadataLookupStatus.Rejected)]
    public async Task GetStringAsync_ClassifiesHttpFailures(
        HttpStatusCode statusCode,
        SafeLookupErrorKind expectedError,
        PackageMetadataLookupStatus expectedStatus)
    {
        var lookup = CreateLookup(statusCode);

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);
        var metadataResult = PackageMetadataLookupResult.FromSafeLookupFailure(result);

        Assert.False(result.Success);
        Assert.Equal(expectedError, result.ErrorKind);
        Assert.Equal(expectedStatus, metadataResult.Status);
        Assert.Contains(((int)statusCode).ToString(), result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetStringAsync_HandlesHttpRequestException()
    {
        var lookup = new SafeHttpLookup(
            ["registry.example.test"],
            new StubHttpHandler(_ => throw new HttpRequestException("Network error")));

        var result = await lookup.GetStringAsync(
            new Uri("https://registry.example.test/package"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(SafeLookupErrorKind.TransportError, result.ErrorKind);
    }

    [Fact]
    public async Task GetStringAsync_ThrowsOnUserCancellation()
    {
        var lookup = CreateLookup(HttpStatusCode.OK);
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
        Assert.Equal("AGPL-3.0-ONLY", agpl.SpdxId);
        Assert.True(agpl.IsPolicySensitive);
        var mixed = PackageLicenseNormalizer.Normalize("MIT AND GPL-3.0-only");
        Assert.Equal(PackageLicenseFamily.Copyleft, mixed.Family);
        Assert.True(mixed.IsPolicySensitive);
        var alternative = PackageLicenseNormalizer.Normalize("MIT OR GPL-3.0-only");
        Assert.Equal(PackageLicenseFamily.Permissive, alternative.Family);
        Assert.False(alternative.IsPolicySensitive);
        Assert.False(PackageLicenseNormalizer.Normalize("custom license text").IsKnown);
        Assert.False(PackageLicenseNormalizer.Normalize(new string('x', 200)).IsKnown);
    }

    private static SafeHttpLookup CreateLookup(HttpStatusCode statusCode, string? body = null) =>
        new(
            ["registry.example.test"],
            new StubHttpHandler(_ => new HttpResponseMessage(statusCode)
            {
                Content = body is null ? null : new StringContent(body, Encoding.UTF8, "application/json")
            }));

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
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(handler(request));
    }
}

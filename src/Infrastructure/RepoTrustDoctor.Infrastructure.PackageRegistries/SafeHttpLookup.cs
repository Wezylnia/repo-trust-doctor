using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public enum SafeLookupErrorKind
{
    BlockedUrl,
    Timeout,
    RateLimited,
    ServerError,
    RejectedRequest,
    TooLarge,
    NotFound,
    MalformedResponse,
    TransportError
}

public sealed record SafeLookupResult(
    bool Success,
    string? Body,
    SafeLookupErrorKind? ErrorKind = null,
    string? ErrorMessage = null)
{
    public static SafeLookupResult Ok(string body) => new(true, body);

    public static SafeLookupResult Fail(SafeLookupErrorKind kind, string message) => new(false, null, kind, message);
}

public sealed class SafeHttpLookup
{
    private readonly HttpClient client;
    private readonly HashSet<string> allowedHosts;
    private readonly int maxRedirects;
    private readonly int maxResponseBytes;
    private readonly TimeSpan timeout;

    public SafeHttpLookup(
        IEnumerable<string> allowedHosts,
        HttpMessageHandler? handler = null,
        int maxRedirects = 3,
        int maxResponseBytes = 1_000_000,
        TimeSpan? timeout = null)
    {
        this.allowedHosts = new HashSet<string>(allowedHosts, StringComparer.OrdinalIgnoreCase);
        this.maxRedirects = maxRedirects;
        this.maxResponseBytes = maxResponseBytes;
        this.timeout = timeout ?? TimeSpan.FromSeconds(10);
        client = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            : new HttpClient(handler, disposeHandler: false);
    }

    public Task<SafeLookupResult> GetStringAsync(Uri uri, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, uri, null, cancellationToken);

    public Task<SafeLookupResult> PostJsonAsync(Uri uri, string json, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Post, uri, json, cancellationToken);

    private async Task<SafeLookupResult> SendAsync(
        HttpMethod method,
        Uri uri,
        string? jsonBody,
        CancellationToken cancellationToken)
    {
        var current = uri;
        for (var redirect = 0; redirect <= maxRedirects; redirect++)
        {
            if (!IsAllowed(current, out var validationError))
            {
                return SafeLookupResult.Fail(SafeLookupErrorKind.BlockedUrl, validationError);
            }

            using var timeoutCts = new CancellationTokenSource(timeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var request = new HttpRequestMessage(method, current);
            if (jsonBody is not null)
            {
                request.Content = new StringContent(jsonBody);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }

            try
            {
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token);
                if (response.StatusCode is HttpStatusCode.NotFound)
                {
                    return SafeLookupResult.Fail(SafeLookupErrorKind.NotFound, "The requested metadata was not found.");
                }

                if (IsRedirect(response.StatusCode))
                {
                    if (redirect == maxRedirects || response.Headers.Location is null)
                    {
                        return SafeLookupResult.Fail(SafeLookupErrorKind.BlockedUrl, "Redirect limit was exceeded or redirect location was missing.");
                    }

                    current = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(current, response.Headers.Location);
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    return ClassifyHttpFailure(response.StatusCode);
                }

                await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token);
                await using var decodedStream = DecodeContentStream(stream, response.Content.Headers.ContentEncoding);
                using var memory = new MemoryStream();
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await decodedStream.ReadAsync(buffer, linkedCts.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    if (memory.Length + read > maxResponseBytes)
                    {
                        return SafeLookupResult.Fail(SafeLookupErrorKind.TooLarge, "The response exceeded the configured byte limit.");
                    }

                    memory.Write(buffer, 0, read);
                }

                return SafeLookupResult.Ok(System.Text.Encoding.UTF8.GetString(memory.ToArray()));
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return SafeLookupResult.Fail(SafeLookupErrorKind.Timeout, "The request timed out.");
            }
            catch (HttpRequestException ex)
            {
                return SafeLookupResult.Fail(SafeLookupErrorKind.TransportError, ex.Message);
            }
        }

        return SafeLookupResult.Fail(SafeLookupErrorKind.BlockedUrl, "Redirect limit was exceeded.");
    }

    private static SafeLookupResult ClassifyHttpFailure(HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        var message = $"The registry returned HTTP status code {code}.";
        return statusCode switch
        {
            HttpStatusCode.RequestTimeout =>
                SafeLookupResult.Fail(SafeLookupErrorKind.Timeout, message),
            HttpStatusCode.TooManyRequests =>
                SafeLookupResult.Fail(SafeLookupErrorKind.RateLimited, message),
            _ when code >= 500 =>
                SafeLookupResult.Fail(SafeLookupErrorKind.ServerError, message),
            _ => SafeLookupResult.Fail(SafeLookupErrorKind.RejectedRequest, message)
        };
    }

    private static Stream DecodeContentStream(Stream stream, ICollection<string> contentEncodings)
    {
        if (contentEncodings.Any(encoding => encoding.Equals("gzip", StringComparison.OrdinalIgnoreCase)))
        {
            return new GZipStream(stream, CompressionMode.Decompress);
        }

        if (contentEncodings.Any(encoding => encoding.Equals("deflate", StringComparison.OrdinalIgnoreCase)))
        {
            return new DeflateStream(stream, CompressionMode.Decompress);
        }

        if (contentEncodings.Any(encoding => encoding.Equals("br", StringComparison.OrdinalIgnoreCase)))
        {
            return new BrotliStream(stream, CompressionMode.Decompress);
        }

        return stream;
    }

    private bool IsAllowed(Uri uri, out string error)
    {
        if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            error = "Only HTTPS URLs are allowed.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            error = "URLs with credentials are not allowed.";
            return false;
        }

        if (!allowedHosts.Contains(uri.Host))
        {
            error = "The host is not allowlisted.";
            return false;
        }

        if (IsBlockedHost(uri.Host))
        {
            error = "Local, private, and link-local hosts are not allowed.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
    {
        var code = (int)statusCode;
        return code is >= 300 and <= 399;
    }

    private static bool IsBlockedHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return bytes[0] == 10 ||
                   bytes[0] == 127 ||
                   bytes[0] == 169 && bytes[1] == 254 ||
                   bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                   bytes[0] == 192 && bytes[1] == 168;
        }

        return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal;
    }
}

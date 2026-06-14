using System.Net;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public interface IOsvFeedSource
{
    Task<Stream> OpenFullArchiveAsync(
        string ecosystem,
        CancellationToken cancellationToken);

    Task<string> GetModifiedIndexAsync(
        string ecosystem,
        CancellationToken cancellationToken);

    Task<string> GetAdvisoryAsync(
        string ecosystem,
        string advisoryId,
        CancellationToken cancellationToken);
}

public sealed class HttpOsvFeedSource : IOsvFeedSource, IDisposable
{
    private const long MaximumArchiveBytes = 4L * 1024 * 1024 * 1024;
    private const int MaximumTextBytes = 64 * 1024 * 1024;
    private readonly HttpClient client;

    public HttpOsvFeedSource(HttpMessageHandler? handler = null)
    {
        client = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            : new HttpClient(handler, disposeHandler: false);
        client.Timeout = TimeSpan.FromMinutes(30);
    }

    public async Task<Stream> OpenFullArchiveAsync(
        string ecosystem,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            BuildUri(ecosystem, "all.zip"),
            cancellationToken);
        if (response.Content.Headers.ContentLength > MaximumArchiveBytes)
        {
            response.Dispose();
            throw new InvalidDataException("OSV archive exceeds the 4 GiB compressed download limit.");
        }

        var tempPath = Path.Combine(
            Path.GetTempPath(),
            $"repo-trust-osv-{Guid.NewGuid():N}.zip");
        try
        {
            using (response)
            await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var output = new FileStream(
                             tempPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             128 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await CopyBoundedAsync(
                    input,
                    output,
                    MaximumArchiveBytes,
                    cancellationToken);
            }

            return new DeleteOnDisposeFileStream(tempPath);
        }
        catch
        {
            File.Delete(tempPath);
            throw;
        }
    }

    public Task<string> GetModifiedIndexAsync(
        string ecosystem,
        CancellationToken cancellationToken) =>
        GetBoundedStringAsync(
            BuildUri(ecosystem, "modified_id.csv"),
            cancellationToken);

    public Task<string> GetAdvisoryAsync(
        string ecosystem,
        string advisoryId,
        CancellationToken cancellationToken) =>
        GetBoundedStringAsync(
            BuildUri(ecosystem, $"{Uri.EscapeDataString(advisoryId)}.json"),
            cancellationToken);

    public void Dispose() => client.Dispose();

    private async Task<string> GetBoundedStringAsync(
        Uri uri,
        CancellationToken cancellationToken)
    {
        using var response = await SendAsync(uri, cancellationToken);
        if (response.Content.Headers.ContentLength > MaximumTextBytes)
        {
            throw new InvalidDataException("OSV text response exceeds the 64 MiB limit.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var memory = new MemoryStream();
        await CopyBoundedAsync(stream, memory, MaximumTextBytes, cancellationToken);
        return System.Text.Encoding.UTF8.GetString(memory.ToArray());
    }

    private async Task<HttpResponseMessage> SendAsync(
        Uri uri,
        CancellationToken cancellationToken)
    {
        if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !uri.Host.Equals(
                "osv-vulnerabilities.storage.googleapis.com",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("OSV feed URL is not allowlisted.");
        }

        var response = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, uri),
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode is HttpStatusCode.Moved or
            HttpStatusCode.Redirect or
            HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect)
        {
            response.Dispose();
            throw new HttpRequestException("OSV feed redirects are not accepted.");
        }

        response.EnsureSuccessStatusCode();
        return response;
    }

    private static Uri BuildUri(string ecosystem, string fileName) =>
        new(
            $"https://osv-vulnerabilities.storage.googleapis.com/{Uri.EscapeDataString(ecosystem)}/{fileName}");

    private static async Task CopyBoundedAsync(
        Stream input,
        Stream output,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            total = checked(total + read);
            if (total > maximumBytes)
            {
                throw new InvalidDataException("OSV download exceeded its configured byte limit.");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private sealed class DeleteOnDisposeFileStream : FileStream
    {
        private readonly string path;

        public DeleteOnDisposeFileStream(string path)
            : base(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan)
        {
            this.path = path;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            File.Delete(path);
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            File.Delete(path);
            GC.SuppressFinalize(this);
        }
    }
}

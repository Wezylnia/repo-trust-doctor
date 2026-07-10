using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.UnitTests;

public sealed class ApiContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = ScanJsonSerializerOptions.Create();

    [Fact]
    public async Task Api_CompletesTheDocumentedScanLifecycleAndExportsEveryReportFormat()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var factory = new ApiFactory(new CompletedScanRunner());
        using var client = factory.CreateClient();

        var health = await client.GetFromJsonAsync<JsonElement>("/health", cancellationToken);
        Assert.Equal("1.0.0", health.GetProperty("version").GetString());
        Assert.Equal("1", health.GetProperty("apiCompatibilityVersion").GetString());

        using var startResponse = await client.PostAsJsonAsync(
            "/api/scans",
            new StartScanRequest("https://github.com/example/repository", "fast", "json", "production"),
            JsonOptions,
            cancellationToken);
        Assert.Equal(HttpStatusCode.Accepted, startResponse.StatusCode);
        var started = await startResponse.Content.ReadFromJsonAsync<StartScanResponse>(JsonOptions, cancellationToken);
        Assert.NotNull(started);

        var status = await WaitForStateAsync(client, started.ScanId, ScanLifecycleState.Completed, cancellationToken);
        Assert.Equal(100, status.OverallScore);
        Assert.Equal(FinalDecisionKind.SafeToTry, status.Decision);
        Assert.Equal($"/api/scans/{started.ScanId}/report?format=json", status.ReportJsonUrl);

        var progress = await client.GetFromJsonAsync<ScanProgressDto>(
            $"/api/scans/{started.ScanId}/progress",
            JsonOptions,
            cancellationToken);
        Assert.NotNull(progress);
        Assert.Equal(1, progress.CompletedModuleCount);
        Assert.Equal(1, progress.TotalModuleCount);
        Assert.Equal(1, progress.CompletionRatio);

        using var modules = await client.GetAsync($"/api/scans/{started.ScanId}/modules", cancellationToken);
        using var findings = await client.GetAsync($"/api/scans/{started.ScanId}/findings", cancellationToken);
        Assert.Equal(HttpStatusCode.OK, modules.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findings.StatusCode);

        await AssertReportAsync(client, started.ScanId, "json", "application/json", "\"toolVersion\": \"1.0.0\"", cancellationToken);
        await AssertReportAsync(client, started.ScanId, "markdown", "text/markdown", "# Repository Trust Report", cancellationToken);
        await AssertReportAsync(client, started.ScanId, "sarif", "application/sarif+json", "\"version\": \"2.1.0\"", cancellationToken);

        using var unsupported = await client.GetAsync($"/api/scans/{started.ScanId}/report?format=xml", cancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, unsupported.StatusCode);
    }

    [Fact]
    public async Task Api_CancelsAnActiveScan()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var factory = new ApiFactory(new BlockingScanRunner());
        using var client = factory.CreateClient();

        using var startResponse = await client.PostAsJsonAsync(
            "/api/scans",
            new StartScanRequest("https://github.com/example/repository"),
            JsonOptions,
            cancellationToken);
        var started = await startResponse.Content.ReadFromJsonAsync<StartScanResponse>(JsonOptions, cancellationToken);
        Assert.NotNull(started);

        using var cancelResponse = await client.PostAsync($"/api/scans/{started.ScanId}/cancel", content: null, cancellationToken);
        Assert.Equal(HttpStatusCode.Accepted, cancelResponse.StatusCode);

        var status = await WaitForStateAsync(client, started.ScanId, ScanLifecycleState.Cancelled, cancellationToken);
        Assert.Equal("Scan cancellation requested.", status.StatusMessage);
    }

    private static async Task<ScanStatusResponse> WaitForStateAsync(
        HttpClient client,
        Guid scanId,
        ScanLifecycleState expected,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var status = await client.GetFromJsonAsync<ScanStatusResponse>($"/api/scans/{scanId}", JsonOptions, cancellationToken);
            Assert.NotNull(status);
            if (status.State == expected)
            {
                return status;
            }

            if (status.State is ScanLifecycleState.Failed or ScanLifecycleState.Cancelled or ScanLifecycleState.Completed)
            {
                Assert.Fail($"Scan reached terminal state {status.State}; expected {expected}.");
            }

            await Task.Delay(20, cancellationToken);
        }

        throw new TimeoutException($"Scan {scanId} did not reach {expected}.");
    }

    private static async Task AssertReportAsync(
        HttpClient client,
        Guid scanId,
        string format,
        string mediaType,
        string expectedText,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"/api/scans/{scanId}/report?format={format}", cancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(mediaType, response.Content.Headers.ContentType?.MediaType);
        Assert.Contains(expectedText, await response.Content.ReadAsStringAsync(cancellationToken));
    }

    private sealed class ApiFactory(IRepositoryScanRunner runner) : WebApplicationFactory<RepoTrustDoctorApiMarker>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRepositoryScanRunner>();
                services.AddSingleton(runner);
            });
        }
    }

    private sealed class CompletedScanRunner : IRepositoryScanRunner
    {
        public Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
        {
            var now = DateTimeOffset.UtcNow;
            var module = new ScanModule(
                "contract",
                "Contract Analyzer",
                AnalysisCategory.RepositoryHealth,
                ModuleStatus.Completed,
                now,
                now,
                0);
            options.Progress?.Invoke(new ScanExecutionProgress(
                ScanLifecycleState.Reporting,
                "Preparing report.",
                [module],
                1));
            return Task.FromResult(new RepositoryScan(
                Guid.NewGuid(),
                options.Target,
                options.Depth,
                options.TrustProfile,
                "1.0.0",
                ModuleStatus.Completed,
                now,
                now,
                [module],
                [],
                new TrustScore(100, [], new FinalDecision(FinalDecisionKind.SafeToTry, []))));
        }
    }

    private sealed class BlockingScanRunner : IRepositoryScanRunner
    {
        public async Task<RepositoryScan> RunAsync(ScanRequestOptions options, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("The blocking runner must be cancelled.");
        }
    }
}

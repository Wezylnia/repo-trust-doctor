using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Contracts;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Reporting;
using RepoTrustDoctor.Shared;

var builder = WebApplication.CreateBuilder(args);
var localWebOrigins = builder.Configuration
    .GetSection("RepoTrustDoctor:WebOrigins")
    .Get<string[]>() ?? ["http://localhost:5174", "http://127.0.0.1:5174"];

builder.Services.AddCors(options =>
{
    options.AddPolicy("LocalWeb", policy =>
    {
        policy
            .WithOrigins(localWebOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});
builder.Services.AddSingleton<IScanStore, InMemoryScanStore>();
builder.Services.AddSingleton<IScanJobQueue, InMemoryScanJobQueue>();
builder.Services.AddSingleton<ScanRequestValidator>();
builder.Services.AddSingleton<ScanCoordinator>();
builder.Services.AddSingleton<IRepositoryScanRunner, DefaultRepositoryScanRunner>();
builder.Services.AddSingleton<ScanJobProcessor>();
builder.Services.AddHostedService<QueuedScanBackgroundService>();
builder.Services.ConfigureHttpJsonOptions(options => ScanJsonSerializerOptions.Configure(options.SerializerOptions));

var app = builder.Build();

app.UseCors("LocalWeb");

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    version = ProductInfo.Version
})).AllowAnonymous();

app.MapPost("/api/scans", async (StartScanRequest request, ScanCoordinator coordinator, CancellationToken cancellationToken) =>
{
    var result = await coordinator.StartAsync(request, cancellationToken);
    if (!result.Accepted)
    {
        return Results.BadRequest(new { error = result.ErrorMessage });
    }

    var statusUrl = $"/api/scans/{result.ScanId}";
    return Results.Accepted(statusUrl, new StartScanResponse(result.ScanId, "Queued", statusUrl));
}).AllowAnonymous();

app.MapGet("/api/scans", (IScanStore store) =>
    Results.Ok(store.List().Select(scan => scan.ToStatusResponse()))).AllowAnonymous();

app.MapGet("/api/scans/{scanId:guid}", (Guid scanId, IScanStore store) =>
    store.TryGet(scanId, out var state) && state is not null
        ? Results.Ok(state.ToStatusResponse())
        : Results.NotFound()).AllowAnonymous();

app.MapGet("/api/scans/{scanId:guid}/progress", (Guid scanId, IScanStore store) =>
    store.TryGet(scanId, out var state) && state is not null
        ? Results.Ok(state.ToProgressDto())
        : Results.NotFound()).AllowAnonymous();

app.MapGet("/api/scans/{scanId:guid}/modules", (Guid scanId, IScanStore store) =>
{
    if (!store.TryGet(scanId, out var state) || state is null)
    {
        return Results.NotFound();
    }

    return state.Result is null
        ? Results.Conflict(new { error = "Scan has not completed yet." })
        : Results.Ok(state.Result.Modules);
}).AllowAnonymous();

app.MapGet("/api/scans/{scanId:guid}/findings", (Guid scanId, IScanStore store) =>
{
    if (!store.TryGet(scanId, out var state) || state is null)
    {
        return Results.NotFound();
    }

    return state.Result is null
        ? Results.Conflict(new { error = "Scan has not completed yet." })
        : Results.Ok(state.Result.Findings);
}).AllowAnonymous();

app.MapGet("/api/scans/{scanId:guid}/report", (Guid scanId, string? format, IScanStore store) =>
{
    if (!store.TryGet(scanId, out var state) || state is null)
    {
        return Results.NotFound();
    }

    if (state.Result is null)
    {
        return Results.Conflict(new { error = "Scan has not completed yet." });
    }

    return (format ?? "json").ToLowerInvariant() switch
    {
        "json" => Results.Text(new JsonReportWriter().Write(state.Result), "application/json"),
        "markdown" or "md" => Results.Text(new MarkdownReportWriter().Write(state.Result), "text/markdown"),
        "sarif" => Results.Text(new SarifReportWriter().Write(state.Result), "application/sarif+json"),
        _ => Results.BadRequest(new { error = "Unsupported report format. Use json, markdown, md, or sarif." })
    };
}).AllowAnonymous();

app.MapPost("/api/scans/{scanId:guid}/cancel", (Guid scanId, ScanCoordinator coordinator) =>
    coordinator.TryCancel(scanId)
        ? Results.Accepted($"/api/scans/{scanId}", new { scanId, status = "CancellationRequested" })
        : Results.NotFound()).AllowAnonymous();

app.Run();

public sealed class QueuedScanBackgroundService(IScanJobQueue queue, ScanJobProcessor processor, ILogger<QueuedScanBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var job = await queue.DequeueAsync(stoppingToken);
                await processor.ProcessAsync(job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unhandled scan worker failure.");
            }
        }
    }
}

public partial class Program;

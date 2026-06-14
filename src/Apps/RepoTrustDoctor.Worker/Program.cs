using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Infrastructure.LocalData;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSingleton<IScanStore, InMemoryScanStore>();
builder.Services.AddSingleton<IScanJobQueue, InMemoryScanJobQueue>();
builder.Services.AddSingleton<ScanRequestValidator>();
builder.Services.AddSingleton<ScanCoordinator>();
var localIntelligenceOptions = builder.Configuration
    .GetSection("RepoTrustDoctor:LocalIntelligence")
    .Get<LocalIntelligenceOptions>() ?? LocalIntelligenceOptions.CreateDefault();
builder.Services.AddSingleton(localIntelligenceOptions);
builder.Services.AddSingleton<IRepositoryScanRunner>(
    _ => new DefaultRepositoryScanRunner(localIntelligenceOptions));
if (localIntelligenceOptions.BackgroundRefreshEnabled)
{
    builder.Services.AddSingleton(
        _ => new LocalIntelligenceRefreshCoordinator(localIntelligenceOptions));
    builder.Services.AddHostedService<LocalIntelligenceRefreshBackgroundService>();
}

builder.Services.AddSingleton<ScanJobProcessor>();
builder.Services.AddHostedService<QueuedScanWorkerService>();

await builder.Build().RunAsync();

public sealed class QueuedScanWorkerService(IScanJobQueue queue, ScanJobProcessor processor, ILogger<QueuedScanWorkerService> logger) : BackgroundService
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

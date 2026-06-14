using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RepoTrustDoctor.Infrastructure.LocalData;

namespace RepoTrustDoctor.Infrastructure.Scanning;

public sealed class LocalIntelligenceRefreshBackgroundService(
    LocalIntelligenceOptions options,
    LocalIntelligenceRefreshCoordinator coordinator,
    ILogger<LocalIntelligenceRefreshBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = options.RefreshInterval > TimeSpan.Zero
            ? options.RefreshInterval
            : TimeSpan.FromHours(24);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await coordinator.RefreshAsync(stoppingToken);
                logger.LogInformation(
                    "Local intelligence refresh completed. Registry: {Refreshed}/{Candidates}, failed: {Failed}. OSV ecosystems: {Succeeded} succeeded, {OsvFailed} failed.",
                    result.Registry.RefreshedCount,
                    result.Registry.CandidateCount,
                    result.Registry.FailedCount,
                    result.Osv.Count(item => item.Succeeded),
                    result.Osv.Count(item => !item.Succeeded));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Local intelligence refresh failed.");
            }

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }
    }
}

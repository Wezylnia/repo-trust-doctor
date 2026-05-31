using System.Diagnostics;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analysis.Engine;

public sealed record AnalyzerExecutionResult(
    IRepositoryAnalyzer Analyzer,
    AnalyzerResult Result,
    ScanModule Module);

public sealed class AnalyzerExecutor
{
    public async Task<AnalyzerExecutionResult> ExecuteAsync(
        IRepositoryAnalyzer analyzer,
        AnalysisContext context,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var result = await analyzer.AnalyzeAsync(context, cancellationToken);

            foreach (var artifact in result.Artifacts ?? [])
            {
                context.AddArtifact(artifact);
            }

            stopwatch.Stop();
            var completed = started.Add(stopwatch.Elapsed);
            var status = result.Status == ModuleStatus.Completed && (result.Warnings?.Count ?? 0) > 0
                ? ModuleStatus.CompletedWithWarnings
                : result.Status;

            return new AnalyzerExecutionResult(
                analyzer,
                result with { Status = status },
                new ScanModule(
                    analyzer.Id,
                    analyzer.DisplayName,
                    analyzer.Category,
                    status,
                    started,
                    completed,
                    result.Findings.Count,
                    result.ErrorMessage));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            var result = new AnalyzerResult(ModuleStatus.Cancelled, []);
            return new AnalyzerExecutionResult(
                analyzer,
                result,
                new ScanModule(analyzer.Id, analyzer.DisplayName, analyzer.Category, ModuleStatus.Cancelled, started, started.Add(stopwatch.Elapsed), 0));
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            var result = new AnalyzerResult(ModuleStatus.Failed, [], ErrorMessage: ex.Message);
            return new AnalyzerExecutionResult(
                analyzer,
                result,
                new ScanModule(analyzer.Id, analyzer.DisplayName, analyzer.Category, ModuleStatus.Failed, started, started.Add(stopwatch.Elapsed), 0, ex.Message));
        }
    }
}

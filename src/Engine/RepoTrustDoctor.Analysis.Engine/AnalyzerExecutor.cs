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
    internal const string UnexpectedFailureMessage = "Analyzer failed unexpectedly.";

    public async Task<AnalyzerExecutionResult> ExecuteAsync(
        IRepositoryAnalyzer analyzer,
        AnalysisContext context,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        using var timeoutCts = new CancellationTokenSource(analyzer.Timeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        try
        {
            var analysisTask = analyzer.AnalyzeAsync(context, linkedCts.Token);
            var result = await analysisTask.WaitAsync(analyzer.Timeout, cancellationToken);

            foreach (var artifact in result.Artifacts ?? [])
            {
                context.AddArtifact(artifact);
            }

            stopwatch.Stop();
            var completed = started.Add(stopwatch.Elapsed);
            var warningDetails = result.WarningDetails ?? AnalyzerWarningClassifier.Classify(result.Warnings);
            var warningMessages = result.Warnings ?? warningDetails.Select(warning => warning.Message).ToArray();
            var hasWarnings = warningMessages.Count > 0;
            var status = result.Status == ModuleStatus.Completed && hasWarnings
                ? ModuleStatus.CompletedWithWarnings
                : result.Status;
            var moduleMessage = status == ModuleStatus.CompletedWithWarnings && hasWarnings
                ? string.Join("; ", warningMessages.Take(3))
                : result.ErrorMessage;

            return new AnalyzerExecutionResult(
                analyzer,
                result with { Status = status, Warnings = warningMessages, WarningDetails = warningDetails },
                new ScanModule(
                    analyzer.Id,
                    analyzer.DisplayName,
                    analyzer.Category,
                    status,
                    started,
                    completed,
                    result.Findings.Count,
                    moduleMessage,
                    Metrics: result.Metrics,
                    Warnings: warningMessages,
                    WarningDetails: warningDetails));
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            var result = new AnalyzerResult(ModuleStatus.TimedOut, []);
            return new AnalyzerExecutionResult(
                analyzer,
                result,
                new ScanModule(analyzer.Id, analyzer.DisplayName, analyzer.Category, ModuleStatus.TimedOut, started, started.Add(stopwatch.Elapsed), 0, $"Analyzer timed out after {analyzer.Timeout.TotalSeconds}s."));
        }
        catch (TimeoutException) when (!cancellationToken.IsCancellationRequested)
        {
            timeoutCts.Cancel();
            stopwatch.Stop();
            var result = new AnalyzerResult(ModuleStatus.TimedOut, []);
            return new AnalyzerExecutionResult(
                analyzer,
                result,
                new ScanModule(analyzer.Id, analyzer.DisplayName, analyzer.Category, ModuleStatus.TimedOut, started, started.Add(stopwatch.Elapsed), 0, $"Analyzer timed out after {analyzer.Timeout.TotalSeconds}s."));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            stopwatch.Stop();
            var result = new AnalyzerResult(ModuleStatus.Failed, [], ErrorMessage: UnexpectedFailureMessage);
            return new AnalyzerExecutionResult(
                analyzer,
                result,
                new ScanModule(analyzer.Id, analyzer.DisplayName, analyzer.Category, ModuleStatus.Failed, started, started.Add(stopwatch.Elapsed), 0, UnexpectedFailureMessage));
        }
    }
}

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
            var warningDetails = (result.WarningDetails ?? AnalyzerWarningClassifier.Classify(result.Warnings))
                .Concat(ValidateEmittedFindings(analyzer, result.Findings))
                .ToArray();
            var warningMessages = warningDetails.Select(warning => warning.Message).ToArray();
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

    private static IReadOnlyList<ScanWarning> ValidateEmittedFindings(
        IRepositoryAnalyzer analyzer,
        IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return [];
        }

        var rulesById = analyzer.Rules.ToDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
        var warnings = new List<ScanWarning>();
        foreach (var finding in findings)
        {
            if (!rulesById.TryGetValue(finding.RuleId, out var rule))
            {
                warnings.Add(CreateValidationWarning(
                    analyzer,
                    $"Analyzer emitted finding '{finding.RuleId}' that is not declared in analyzer.Rules."));
                continue;
            }

            if (finding.Category != rule.Category)
            {
                warnings.Add(CreateValidationWarning(
                    analyzer,
                    $"Analyzer emitted finding '{finding.RuleId}' with category '{finding.Category}' but rule metadata declares '{rule.Category}'."));
            }

            if (finding.Evidence.Count == 0)
            {
                warnings.Add(CreateValidationWarning(
                    analyzer,
                    $"Analyzer emitted finding '{finding.RuleId}' without evidence."));
            }

            if (string.IsNullOrWhiteSpace(finding.Recommendation.Message))
            {
                warnings.Add(CreateValidationWarning(
                    analyzer,
                    $"Analyzer emitted finding '{finding.RuleId}' without a recommendation."));
            }
        }

        return warnings;
    }

    private static ScanWarning CreateValidationWarning(IRepositoryAnalyzer analyzer, string message) =>
        new(
            ScanWarningKind.AnalyzerFailure,
            $"{analyzer.Id}: {message}",
            AffectsCoverage: true);
}

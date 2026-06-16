using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Reporting;

namespace RepoTrustDoctor.TrustHistory;

public sealed class TrustSnapshotFactory
{
    public ScanSnapshot Create(RepositoryScan scan)
    {
        var findings = FindingFingerprinter.AddFingerprints(scan.Findings)
            .Select(finding =>
            {
                var primaryEvidence = finding.Evidence.FirstOrDefault(evidence => !string.IsNullOrWhiteSpace(evidence.FilePath))
                    ?? finding.Evidence.FirstOrDefault();

                return new FindingSnapshot(
                    finding.Fingerprint ?? FindingFingerprinter.Compute(finding),
                    finding.RuleId,
                    finding.Title,
                    finding.Category,
                    finding.Severity,
                    finding.IsBlocking,
                    primaryEvidence?.FilePath?.Replace('\\', '/'));
            })
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(finding => finding.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ScanSnapshot(
            scan.Id,
            scan.Target,
            scan.Depth,
            scan.TrustProfile,
            scan.ToolVersion,
            scan.CompletedAt,
            scan.Score.Overall,
            scan.Score.Decision.Kind,
            scan.Score.Categories
                .Select(category => new CategoryScoreSnapshot(category.Category, category.Score))
                .OrderBy(category => category.Category)
                .ToArray(),
            scan.Summary,
            findings);
    }
}

public sealed class TrustDiffEngine
{
    public TrustDiffResult Compare(ScanSnapshot before, ScanSnapshot after)
    {
        var beforeFindings = before.Findings.ToDictionary(finding => finding.Fingerprint, StringComparer.OrdinalIgnoreCase);
        var afterFindings = after.Findings.ToDictionary(finding => finding.Fingerprint, StringComparer.OrdinalIgnoreCase);

        var newFindings = after.Findings
            .Where(finding => !beforeFindings.ContainsKey(finding.Fingerprint))
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var resolvedFindings = before.Findings
            .Where(finding => !afterFindings.ContainsKey(finding.Fingerprint))
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var matched = after.Findings
            .Where(finding => beforeFindings.ContainsKey(finding.Fingerprint))
            .Select(finding => new FindingChange(beforeFindings[finding.Fingerprint], finding))
            .ToArray();

        var worsened = matched
            .Where(change => change.After.Severity > change.Before.Severity || (!change.Before.IsBlocking && change.After.IsBlocking))
            .OrderByDescending(change => change.After.Severity)
            .ToArray();

        var improved = matched
            .Where(change => change.After.Severity < change.Before.Severity || (change.Before.IsBlocking && !change.After.IsBlocking))
            .OrderByDescending(change => change.Before.Severity)
            .ToArray();

        var unchanged = matched
            .Where(change => change.After.Severity == change.Before.Severity && change.After.IsBlocking == change.Before.IsBlocking)
            .Select(change => change.After)
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new TrustDiffResult(
            before,
            after,
            after.OverallScore - before.OverallScore,
            before.Decision != after.Decision,
            BuildCategoryDeltas(before, after),
            newFindings,
            resolvedFindings,
            worsened,
            improved,
            unchanged);
    }

    private static IReadOnlyList<CategoryScoreDelta> BuildCategoryDeltas(ScanSnapshot before, ScanSnapshot after)
    {
        var beforeByCategory = before.CategoryScores.ToDictionary(category => category.Category, category => category.Score);
        var afterByCategory = after.CategoryScores.ToDictionary(category => category.Category, category => category.Score);
        return beforeByCategory.Keys
            .Union(afterByCategory.Keys)
            .Order()
            .Select(category =>
            {
                var hasBefore = beforeByCategory.TryGetValue(category, out var beforeScore);
                var hasAfter = afterByCategory.TryGetValue(category, out var afterScore);
                return (hasBefore, hasAfter) switch
                {
                    (true, true) => new CategoryScoreDelta(
                        category,
                        beforeScore,
                        afterScore,
                        afterScore - beforeScore,
                        CategoryScoreComparisonState.Comparable),
                    (false, true) => new CategoryScoreDelta(
                        category,
                        null,
                        afterScore,
                        null,
                        CategoryScoreComparisonState.NewlyEvaluated),
                    (true, false) => new CategoryScoreDelta(
                        category,
                        beforeScore,
                        null,
                        null,
                        CategoryScoreComparisonState.NoLongerEvaluated),
                    _ => throw new InvalidOperationException("Category union produced an empty category delta.")
                };
            })
            .ToArray();
    }
}

public sealed class RepositoryComparisonEngine
{
    public RepositoryComparisonResult Compare(IReadOnlyList<ScanSnapshot> snapshots)
    {
        var entries = snapshots
            .Select(snapshot => new RepositoryComparisonEntry(
                snapshot.Target,
                snapshot.OverallScore,
                snapshot.Decision,
                snapshot.FindingSummary,
                snapshot.Findings
                    .Where(finding => finding.Severity >= Severity.High || finding.IsBlocking)
                    .OrderByDescending(finding => finding.IsBlocking)
                    .ThenByDescending(finding => finding.Severity)
                    .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
                    .Take(5)
                    .ToArray()))
            .OrderBy(entry => entry.OverallScore)
            .ThenByDescending(entry => entry.FindingSummary.Critical)
            .ThenByDescending(entry => entry.FindingSummary.High)
            .ToArray();

        return new RepositoryComparisonResult(entries);
    }
}

public sealed class TrustRegressionDetector
{
    public IReadOnlyList<TrustRegressionAlert> Detect(TrustDiffResult diff, ScheduledScanDefinition? schedule = null)
    {
        var scoreDropThreshold = schedule?.ScoreDropAlertThreshold ?? 10;
        var newFindingSeverity = schedule?.NewFindingAlertSeverity ?? Severity.High;
        var alerts = new List<TrustRegressionAlert>();

        if (diff.OverallScoreDelta <= -scoreDropThreshold)
        {
            alerts.Add(new TrustRegressionAlert(
                TrustRegressionAlertKind.ScoreDrop,
                Severity.Medium,
                $"Trust score dropped by {Math.Abs(diff.OverallScoreDelta)} points."));
        }

        if (IsDecisionWorse(diff.Before.Decision, diff.After.Decision))
        {
            alerts.Add(new TrustRegressionAlert(
                TrustRegressionAlertKind.DecisionWorsened,
                Severity.High,
                $"Final decision worsened from {diff.Before.Decision} to {diff.After.Decision}."));
        }

        alerts.AddRange(diff.NewFindings
            .Where(finding => finding.IsBlocking)
            .Select(finding => new TrustRegressionAlert(
                TrustRegressionAlertKind.NewBlockingFinding,
                finding.Severity,
                $"New blocking finding: {finding.RuleId} - {finding.Title}.",
                finding.Fingerprint)));

        alerts.AddRange(diff.NewFindings
            .Where(finding => !finding.IsBlocking && finding.Severity >= newFindingSeverity)
            .Select(finding => new TrustRegressionAlert(
                TrustRegressionAlertKind.NewHighSeverityFinding,
                finding.Severity,
                $"New {finding.Severity} finding: {finding.RuleId} - {finding.Title}.",
                finding.Fingerprint)));

        return alerts;
    }

    private static bool IsDecisionWorse(FinalDecisionKind before, FinalDecisionKind after) =>
        DecisionRank(after) > DecisionRank(before);

    private static int DecisionRank(FinalDecisionKind decision) => decision switch
    {
        FinalDecisionKind.SafeToTry => 0,
        FinalDecisionKind.UseWithCaution => 1,
        FinalDecisionKind.NeedsManualReview => 2,
        FinalDecisionKind.AvoidAsProductionDependency => 3,
        _ => 2
    };
}

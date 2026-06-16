using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.TrustHistory;

public sealed record ScanSnapshot(
    Guid ScanId,
    string Target,
    AnalysisDepth Depth,
    TrustProfile TrustProfile,
    string ToolVersion,
    DateTimeOffset ScannedAt,
    int OverallScore,
    FinalDecisionKind Decision,
    IReadOnlyList<CategoryScoreSnapshot> CategoryScores,
    FindingSummary FindingSummary,
    IReadOnlyList<FindingSnapshot> Findings);

public sealed record CategoryScoreSnapshot(AnalysisCategory Category, int Score);

public sealed record FindingSnapshot(
    string Fingerprint,
    string RuleId,
    string Title,
    AnalysisCategory Category,
    Severity Severity,
    bool IsBlocking,
    string? FilePath);

public sealed record TrustDiffResult(
    ScanSnapshot Before,
    ScanSnapshot After,
    int OverallScoreDelta,
    bool DecisionChanged,
    TrustDiffComparability Comparability,
    IReadOnlyList<string> ComparabilityReasons,
    IReadOnlyList<CategoryScoreDelta> CategoryDeltas,
    IReadOnlyList<FindingSnapshot> NewFindings,
    IReadOnlyList<FindingSnapshot> ResolvedFindings,
    IReadOnlyList<FindingChange> WorsenedFindings,
    IReadOnlyList<FindingChange> ImprovedFindings,
    IReadOnlyList<FindingSnapshot> UnchangedFindings);

public sealed record CategoryScoreDelta(
    AnalysisCategory Category,
    int? BeforeScore,
    int? AfterScore,
    int? Delta,
    CategoryScoreComparisonState State);

public enum CategoryScoreComparisonState
{
    Comparable,
    NewlyEvaluated,
    NoLongerEvaluated
}

public enum TrustDiffComparability
{
    Direct,
    Partial,
    DifferentTarget
}

public sealed record FindingChange(FindingSnapshot Before, FindingSnapshot After);

public sealed record RepositoryComparisonResult(IReadOnlyList<RepositoryComparisonEntry> Repositories);

public sealed record RepositoryComparisonEntry(
    string Target,
    int OverallScore,
    FinalDecisionKind Decision,
    FindingSummary FindingSummary,
    IReadOnlyList<FindingSnapshot> TopRisks);

public sealed record TrustRegressionAlert(
    TrustRegressionAlertKind Kind,
    Severity Severity,
    string Message,
    string? Fingerprint = null);

public enum TrustRegressionAlertKind
{
    ScoreDrop,
    DecisionWorsened,
    NewBlockingFinding,
    NewHighSeverityFinding
}

public sealed record ScheduledScanDefinition(
    string Id,
    string Target,
    TrustProfile TrustProfile,
    AnalysisDepth Depth,
    string CronExpression,
    int ScoreDropAlertThreshold = 10,
    Severity NewFindingAlertSeverity = Severity.High);

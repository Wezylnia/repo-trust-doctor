using RepoTrustDoctor.Domain;
using RepoTrustDoctor.TrustHistory;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustHistoryTests
{
    [Fact]
    public void TrustSnapshotFactory_CreatesStableFindingSnapshots()
    {
        var scan = CreateScan("repo-a", 90, FinalDecisionKind.SafeToTry, [
            CreateFinding("TRUST-TEST001", Severity.High, "src/App.cs")
        ]);

        var snapshot = new TrustSnapshotFactory().Create(scan);

        var finding = Assert.Single(snapshot.Findings);
        Assert.False(string.IsNullOrWhiteSpace(finding.Fingerprint));
        Assert.Equal("src/App.cs", finding.FilePath);
        Assert.Equal(90, snapshot.OverallScore);
        Assert.Equal(FinalDecisionKind.SafeToTry, snapshot.Decision);
    }

    [Fact]
    public void TrustDiffEngine_TracksNewResolvedAndCategoryDeltas()
    {
        var beforeFinding = FindingSnapshot("fp-resolved", "TRUST-OLD", Severity.Medium, false);
        var unchangedFinding = FindingSnapshot("fp-same", "TRUST-SAME", Severity.Low, false);
        var before = Snapshot("repo", 88, FinalDecisionKind.SafeToTry, [beforeFinding, unchangedFinding]);
        var after = Snapshot("repo", 72, FinalDecisionKind.UseWithCaution, [
            unchangedFinding,
            FindingSnapshot("fp-new", "TRUST-NEW", Severity.High, true)
        ]);

        var diff = new TrustDiffEngine().Compare(before, after);

        Assert.Equal(-16, diff.OverallScoreDelta);
        Assert.True(diff.DecisionChanged);
        Assert.Equal("TRUST-NEW", Assert.Single(diff.NewFindings).RuleId);
        Assert.Equal("TRUST-OLD", Assert.Single(diff.ResolvedFindings).RuleId);
        Assert.Equal("TRUST-SAME", Assert.Single(diff.UnchangedFindings).RuleId);
        Assert.Contains(diff.CategoryDeltas, delta => delta.Category == AnalysisCategory.Security && delta.Delta == -16);
    }

    [Fact]
    public void TrustDiffEngine_DoesNotTreatUnevaluatedCategoryAsZero()
    {
        var before = Snapshot(
            "repo",
            90,
            FinalDecisionKind.SafeToTry,
            [],
            [new CategoryScoreSnapshot(AnalysisCategory.Security, 90)]);
        var after = Snapshot(
            "repo",
            88,
            FinalDecisionKind.SafeToTry,
            [],
            [
                new CategoryScoreSnapshot(AnalysisCategory.Security, 90),
                new CategoryScoreSnapshot(AnalysisCategory.Codebase, 88)
            ]);

        var diff = new TrustDiffEngine().Compare(before, after);

        var security = Assert.Single(diff.CategoryDeltas, delta => delta.Category == AnalysisCategory.Security);
        Assert.Equal(CategoryScoreComparisonState.Comparable, security.State);
        Assert.Equal(0, security.Delta);

        var codebase = Assert.Single(diff.CategoryDeltas, delta => delta.Category == AnalysisCategory.Codebase);
        Assert.Equal(CategoryScoreComparisonState.NewlyEvaluated, codebase.State);
        Assert.Null(codebase.BeforeScore);
        Assert.Equal(88, codebase.AfterScore);
        Assert.Null(codebase.Delta);
    }

    [Fact]
    public void TrustDiffEngine_MarksCategoryThatIsNoLongerEvaluated()
    {
        var before = Snapshot(
            "repo",
            88,
            FinalDecisionKind.SafeToTry,
            [],
            [
                new CategoryScoreSnapshot(AnalysisCategory.Security, 90),
                new CategoryScoreSnapshot(AnalysisCategory.Codebase, 88)
            ]);
        var after = Snapshot(
            "repo",
            90,
            FinalDecisionKind.SafeToTry,
            [],
            [new CategoryScoreSnapshot(AnalysisCategory.Security, 90)]);

        var diff = new TrustDiffEngine().Compare(before, after);

        var codebase = Assert.Single(diff.CategoryDeltas, delta => delta.Category == AnalysisCategory.Codebase);
        Assert.Equal(CategoryScoreComparisonState.NoLongerEvaluated, codebase.State);
        Assert.Equal(88, codebase.BeforeScore);
        Assert.Null(codebase.AfterScore);
        Assert.Null(codebase.Delta);
    }

    [Fact]
    public void TrustDiffEngine_TracksWorsenedAndImprovedMatchedFindings()
    {
        var before = Snapshot("repo", 80, FinalDecisionKind.UseWithCaution, [
            FindingSnapshot("fp-worse", "TRUST-WORSE", Severity.Low, false),
            FindingSnapshot("fp-better", "TRUST-BETTER", Severity.High, true)
        ]);
        var after = Snapshot("repo", 82, FinalDecisionKind.UseWithCaution, [
            FindingSnapshot("fp-worse", "TRUST-WORSE", Severity.High, true),
            FindingSnapshot("fp-better", "TRUST-BETTER", Severity.Low, false)
        ]);

        var diff = new TrustDiffEngine().Compare(before, after);

        Assert.Equal("TRUST-WORSE", Assert.Single(diff.WorsenedFindings).After.RuleId);
        Assert.Equal("TRUST-BETTER", Assert.Single(diff.ImprovedFindings).After.RuleId);
    }

    [Fact]
    public void TrustDiffEngine_TreatsLineOnlyMovementAsUnchanged()
    {
        var beforeScan = CreateScan("repo", 80, FinalDecisionKind.UseWithCaution, [
            CreateFinding("TRUST-CODE015", Severity.High, "src/App.cs", 12)
        ]);
        var afterScan = CreateScan("repo", 80, FinalDecisionKind.UseWithCaution, [
            CreateFinding("TRUST-CODE015", Severity.High, "src/App.cs", 18)
        ]);
        var factory = new TrustSnapshotFactory();

        var diff = new TrustDiffEngine().Compare(factory.Create(beforeScan), factory.Create(afterScan));

        Assert.Empty(diff.NewFindings);
        Assert.Empty(diff.ResolvedFindings);
        Assert.Single(diff.UnchangedFindings);
    }

    [Fact]
    public void RepositoryComparisonEngine_SortsLowestTrustRepositoriesFirst()
    {
        var result = new RepositoryComparisonEngine().Compare([
            Snapshot("repo-good", 92, FinalDecisionKind.SafeToTry, []),
            Snapshot("repo-risky", 41, FinalDecisionKind.AvoidAsProductionDependency, [
                FindingSnapshot("fp-critical", "TRUST-CRIT", Severity.Critical, true)
            ]),
            Snapshot("repo-mid", 70, FinalDecisionKind.UseWithCaution, [])
        ]);

        Assert.Equal(["repo-risky", "repo-mid", "repo-good"], result.Repositories.Select(entry => entry.Target));
        Assert.Equal("TRUST-CRIT", Assert.Single(result.Repositories[0].TopRisks).RuleId);
    }

    [Fact]
    public void TrustRegressionDetector_EmitsScoreDecisionAndNewFindingAlerts()
    {
        var before = Snapshot("repo", 90, FinalDecisionKind.SafeToTry, []);
        var after = Snapshot("repo", 70, FinalDecisionKind.AvoidAsProductionDependency, [
            FindingSnapshot("fp-new", "TRUST-NEW", Severity.High, true)
        ]);
        var diff = new TrustDiffEngine().Compare(before, after);

        var alerts = new TrustRegressionDetector().Detect(diff);

        Assert.Contains(alerts, alert => alert.Kind == TrustRegressionAlertKind.ScoreDrop);
        Assert.Contains(alerts, alert => alert.Kind == TrustRegressionAlertKind.DecisionWorsened);
        Assert.Contains(alerts, alert => alert.Kind == TrustRegressionAlertKind.NewBlockingFinding);
    }

    private static RepositoryScan CreateScan(string target, int score, FinalDecisionKind decision, IReadOnlyList<Finding> findings) =>
        new(
            Guid.NewGuid(),
            target,
            AnalysisDepth.Deep,
            TrustProfile.ProductionDependency,
            "test",
            ModuleStatus.Completed,
            DateTimeOffset.Parse("2026-06-10T00:00:00Z"),
            DateTimeOffset.Parse("2026-06-10T00:00:01Z"),
            [],
            findings,
            new TrustScore(score, [new CategoryScore(AnalysisCategory.Security, score)], new FinalDecision(decision, [])),
            null);

    private static Finding CreateFinding(string ruleId, Severity severity, string filePath, int? lineNumber = null) =>
        new(
            ruleId,
            "Test finding",
            AnalysisCategory.Security,
            severity,
            Confidence.High,
            "Test finding.",
            [new Evidence("test", "test", filePath, lineNumber)],
            new Recommendation("Fix it."));

    private static ScanSnapshot Snapshot(
        string target,
        int score,
        FinalDecisionKind decision,
        IReadOnlyList<FindingSnapshot> findings,
        IReadOnlyList<CategoryScoreSnapshot>? categoryScores = null) =>
        new(
            Guid.NewGuid(),
            target,
            AnalysisDepth.Deep,
            TrustProfile.ProductionDependency,
            "test",
            DateTimeOffset.Parse("2026-06-10T00:00:01Z"),
            score,
            decision,
            categoryScores ?? [new CategoryScoreSnapshot(AnalysisCategory.Security, score)],
            new FindingSummary(
                findings.Count,
                findings.Count(finding => finding.Severity == Severity.Critical),
                findings.Count(finding => finding.Severity == Severity.High),
                findings.Count(finding => finding.Severity == Severity.Medium),
                findings.Count(finding => finding.Severity == Severity.Low),
                findings.Count(finding => finding.Severity == Severity.Info),
                findings.Count(finding => finding.IsBlocking)),
            findings);

    private static FindingSnapshot FindingSnapshot(string fingerprint, string ruleId, Severity severity, bool isBlocking) =>
        new(fingerprint, ruleId, ruleId, AnalysisCategory.Security, severity, isBlocking, "src/App.cs");
}

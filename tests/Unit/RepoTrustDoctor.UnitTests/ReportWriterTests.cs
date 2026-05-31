using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Reporting;

namespace RepoTrustDoctor.UnitTests;

public sealed class ReportWriterTests
{
    [Fact]
    public void JsonReport_IncludesToolVersion()
    {
        var scan = CreateMinimalScan();
        var json = new JsonReportWriter().Write(scan);

        Assert.Contains("0.1.0-alpha", json);
        Assert.Contains("toolVersion", json);
    }

    [Fact]
    public void MarkdownReport_IncludesToolVersion()
    {
        var scan = CreateMinimalScan();
        var md = new MarkdownReportWriter().Write(scan);

        Assert.Contains("0.1.0-alpha", md);
        Assert.Contains("Tool version", md);
    }

    [Fact]
    public void JsonReport_IncludesSelectedTrustProfile()
    {
        var scan = CreateMinimalScan();
        var json = new JsonReportWriter().Write(scan);

        Assert.Contains("trustProfile", json);
        Assert.Contains("ProductionDependency", json);
    }

    [Fact]
    public void MarkdownReport_IncludesSelectedTrustProfile()
    {
        var scan = CreateMinimalScan();
        var md = new MarkdownReportWriter().Write(scan);

        Assert.Contains("Trust profile", md);
        Assert.Contains("ProductionDependency", md);
    }

    [Fact]
    public void SortFindings_OrdersBySeverityDescending_ThenByCategory_ThenByRuleId()
    {
        var findings = new List<Finding>
        {
            CreateFinding("TRUST-B002", Severity.Low, AnalysisCategory.Security),
            CreateFinding("TRUST-A001", Severity.High, AnalysisCategory.CiCd),
            CreateFinding("TRUST-C003", Severity.High, AnalysisCategory.Security),
            CreateFinding("TRUST-A001", Severity.Low, AnalysisCategory.CiCd),
        };

        var sorted = JsonReportWriter.SortFindings(findings);

        Assert.Equal("TRUST-A001", sorted[0].RuleId);
        Assert.Equal(Severity.High, sorted[0].Severity);
        Assert.Equal(AnalysisCategory.CiCd, sorted[0].Category);

        Assert.Equal("TRUST-C003", sorted[1].RuleId);
        Assert.Equal(Severity.High, sorted[1].Severity);

        Assert.Equal("TRUST-A001", sorted[2].RuleId);
        Assert.Equal(Severity.Low, sorted[2].Severity);

        Assert.Equal("TRUST-B002", sorted[3].RuleId);
        Assert.Equal(Severity.Low, sorted[3].Severity);
    }

    [Fact]
    public void FindingSummary_CountsAreCorrect()
    {
        var findings = new List<Finding>
        {
            CreateFinding("R1", Severity.Critical, AnalysisCategory.Security, isBlocking: true),
            CreateFinding("R2", Severity.High, AnalysisCategory.Security),
            CreateFinding("R3", Severity.Medium, AnalysisCategory.CiCd),
            CreateFinding("R4", Severity.Low, AnalysisCategory.CiCd),
            CreateFinding("R5", Severity.Info, AnalysisCategory.RepositoryHealth),
        };

        var summary = FindingSummary.From(findings);

        Assert.Equal(5, summary.Total);
        Assert.Equal(1, summary.Critical);
        Assert.Equal(1, summary.High);
        Assert.Equal(1, summary.Medium);
        Assert.Equal(1, summary.Low);
        Assert.Equal(1, summary.Info);
        Assert.Equal(1, summary.Blocking);
    }

    [Fact]
    public void MarkdownReport_ShowsSummaryTable()
    {
        var scan = CreateMinimalScan();
        var md = new MarkdownReportWriter().Write(scan);

        Assert.Contains("Finding Summary", md);
        Assert.Contains("Severity", md);
        Assert.Contains("Count", md);
    }

    [Fact]
    public void JsonReport_IncludesSummary()
    {
        var scan = CreateMinimalScan();
        var json = new JsonReportWriter().Write(scan);

        Assert.Contains("summary", json);
    }

    private static RepositoryScan CreateMinimalScan()
    {
        return new RepositoryScan(
            Guid.NewGuid(),
            ".",
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            "0.1.0-alpha",
            ModuleStatus.Completed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            [],
            [],
            new TrustScore(100, [], new FinalDecision(FinalDecisionKind.SafeToTry, ["No findings."])));
    }

    private static Finding CreateFinding(string ruleId, Severity severity, AnalysisCategory category, bool isBlocking = false)
    {
        return new Finding(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            $"Message for {ruleId}",
            [new Evidence("test", "test evidence")],
            new Recommendation("Fix it."),
            isBlocking);
    }
}

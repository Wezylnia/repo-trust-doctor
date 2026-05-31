using System.Text.Json;
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

    [Fact]
    public void JsonReport_ProducesStableFindingFingerprintAcrossReportWrites()
    {
        var finding = CreateFinding(
            "TRUST-SECRET005",
            Severity.High,
            AnalysisCategory.Security,
            evidenceKind: "secret-pattern",
            filePath: "src/appsettings.json",
            lineNumber: 42);
        var scan = CreateMinimalScan() with { Findings = [finding] };
        var writer = new JsonReportWriter();

        var firstFingerprint = ExtractFirstFindingFingerprint(writer.Write(scan));
        var secondFingerprint = ExtractFirstFindingFingerprint(writer.Write(scan));

        Assert.Matches("^[a-f0-9]{64}$", firstFingerprint);
        Assert.Equal(firstFingerprint, secondFingerprint);
    }

    [Fact]
    public void MarkdownReport_IncludesFindingFingerprint()
    {
        var finding = CreateFinding(
            "TRUST-GHA007",
            Severity.Low,
            AnalysisCategory.CiCd,
            evidenceKind: "workflow-step",
            filePath: ".github/workflows/ci.yml",
            lineNumber: 12);
        var scan = CreateMinimalScan() with { Findings = [finding] };

        var markdown = new MarkdownReportWriter().Write(scan);

        Assert.Contains("Fingerprint", markdown);
        Assert.Contains(FindingFingerprinter.Compute(finding), markdown);
    }

    [Fact]
    public void FindingFingerprint_ChangesWhenLineNumberChanges()
    {
        var first = CreateFinding(
            "TRUST-GHA007",
            Severity.Low,
            AnalysisCategory.CiCd,
            evidenceKind: "workflow-step",
            filePath: ".github/workflows/ci.yml",
            lineNumber: 12);
        var second = CreateFinding(
            "TRUST-GHA007",
            Severity.Low,
            AnalysisCategory.CiCd,
            evidenceKind: "workflow-step",
            filePath: ".github/workflows/ci.yml",
            lineNumber: 13);

        Assert.NotEqual(FindingFingerprinter.Compute(first), FindingFingerprinter.Compute(second));
    }

    [Fact]
    public void FindingFingerprint_IgnoresEvidenceValues()
    {
        var first = CreateFinding(
            "TRUST-SECRET005",
            Severity.High,
            AnalysisCategory.Security,
            evidenceKind: "secret-pattern",
            filePath: "src/appsettings.json",
            lineNumber: 42,
            evidenceValue: "postgres://user:raw-secret-one@example/db");
        var second = CreateFinding(
            "TRUST-SECRET005",
            Severity.High,
            AnalysisCategory.Security,
            evidenceKind: "secret-pattern",
            filePath: "src/appsettings.json",
            lineNumber: 42,
            evidenceValue: "postgres://user:raw-secret-two@example/db");

        Assert.Equal(FindingFingerprinter.Compute(first), FindingFingerprinter.Compute(second));
    }

    private static string ExtractFirstFindingFingerprint(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement
            .GetProperty("findings")[0]
            .GetProperty("fingerprint")
            .GetString()!;
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

    private static Finding CreateFinding(
        string ruleId,
        Severity severity,
        AnalysisCategory category,
        bool isBlocking = false,
        string evidenceKind = "test",
        string? filePath = null,
        int? lineNumber = null,
        string? evidenceValue = null)
    {
        return new Finding(
            ruleId,
            $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            $"Message for {ruleId}",
            [new Evidence(evidenceKind, "test evidence", filePath, lineNumber, evidenceValue)],
            new Recommendation("Fix it."),
            isBlocking);
    }
}

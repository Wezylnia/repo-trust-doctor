using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Reporting;
using RepoTrustDoctor.Shared;

namespace RepoTrustDoctor.UnitTests;

public sealed class ReportWriterTests
{
    [Fact]
    public void JsonReport_IncludesToolVersion()
    {
        var scan = CreateMinimalScan();
        var json = new JsonReportWriter().Write(scan);

        Assert.Contains(ProductInfo.Version, json);
        Assert.Contains("toolVersion", json);
    }

    [Fact]
    public void MarkdownReport_IncludesToolVersion()
    {
        var scan = CreateMinimalScan();
        var md = new MarkdownReportWriter().Write(scan);

        Assert.Contains(ProductInfo.Version, md);
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
    public void MarkdownReport_IncludesDependencyInventorySummary_WhenArtifactExists()
    {
        var inventory = new DependencyInventoryArtifact(
            [new DependencyManifestInfo(DependencyEcosystem.Npm, "package.json", "package.json")],
            [new DependencyLockfileInfo(DependencyEcosystem.Npm, "package-lock.json", "package-lock.json")],
            [
                new DependencyPackageInfo(
                    DependencyEcosystem.Npm,
                    "react",
                    "^19.0.0",
                    DependencyScope.Production,
                    "package.json",
                    "package-lock.json",
                    true,
                    false,
                    false)
            ],
            [],
            new Dictionary<string, string>());
        var scan = CreateMinimalScan() with
        {
            Artifacts = new Dictionary<string, object>
            {
                [DependencyInventoryArtifact.ArtifactKey] = inventory
            }
        };

        var markdown = new MarkdownReportWriter().Write(scan);

        Assert.Contains("Dependency Inventory", markdown);
        Assert.Contains("| Npm | 1 | 1 | 1 |", markdown);
        Assert.Contains("Unpinned or ranged packages", markdown);
        Assert.Contains("Direct remote npm sources", markdown);
        Assert.Contains("Insecure package sources", markdown);
    }

    [Fact]
    public void MarkdownReport_IncludesTopRecommendedActions()
    {
        var scan = CreateMinimalScan() with
        {
            Findings =
            [
                CreateFinding("TRUST-DEP006", Severity.Medium, AnalysisCategory.Dependencies),
                CreateFinding("TRUST-GHA001", Severity.High, AnalysisCategory.CiCd)
            ]
        };

        var markdown = new MarkdownReportWriter().Write(scan);

        Assert.Contains("Top Recommended Actions", markdown);
        Assert.Contains("Fix it.", markdown);
    }

    [Fact]
    public void MarkdownReport_LimitsRenderedFindingsWithoutDroppingJsonFindings()
    {
        var findings = Enumerable
            .Range(1, 101)
            .Select(index => CreateFinding(
                $"TRUST-TEST{index:000}",
                Severity.Low,
                AnalysisCategory.RepositoryHealth,
                filePath: $"file-{index}.txt"))
            .ToArray();
        var scan = CreateMinimalScan() with { Findings = findings };

        var markdown = new MarkdownReportWriter().Write(scan);
        var json = new JsonReportWriter().Write(scan);

        Assert.Contains("Showing 100 of 101 findings.", markdown);
        Assert.Contains("The remaining 1 findings are omitted from this Markdown view", markdown);
        Assert.Contains("TRUST-TEST100", markdown);
        Assert.DoesNotContain("TRUST-TEST101", markdown);

        using var document = JsonDocument.Parse(json);
        Assert.Equal(101, document.RootElement.GetProperty("findings").GetArrayLength());
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
    public void MarkdownReport_EscapesFindingContentThatCouldAlterDocumentStructure()
    {
        var finding = CreateFinding(
            "TRUST-MD001",
            Severity.High,
            AnalysisCategory.Security,
            title: "Injected\n## Forged heading",
            message: "Message | cell\n- forged list\n<script>alert(1)</script>",
            evidenceMessage: "Evidence | value\n### forged evidence",
            filePath: "src/`danger`.cs",
            recommendation: "Fix | now\n# forged recommendation <b>");
        var scan = CreateMinimalScan() with { Findings = [finding] };

        var markdown = new MarkdownReportWriter().Write(scan);

        Assert.DoesNotContain("\n## Forged heading", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("\n### forged evidence", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<b>", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Injected \\#\\# Forged heading", markdown);
        Assert.Contains("Message \\| cell - forged list &lt;script&gt;alert\\(1\\)&lt;/script&gt;", markdown);
        Assert.Contains("Evidence \\| value \\#\\#\\# forged evidence", markdown);
        Assert.Contains("Fix \\| now \\# forged recommendation &lt;b&gt;", markdown);
        Assert.Contains("``src/`danger`.cs``", markdown);
    }

    [Fact]
    public void MarkdownReport_IncludesModuleWarningsFailuresAndSkippedReasons()
    {
        var now = DateTimeOffset.UtcNow;
        var scan = CreateMinimalScan() with
        {
            Status = ModuleStatus.CompletedWithWarnings,
            Modules =
            [
                new ScanModule(
                    "inventory",
                    "Inventory",
                    AnalysisCategory.Dependencies,
                    ModuleStatus.CompletedWithWarnings,
                    now,
                    now,
                    0,
                    Warnings: ["Cargo.lock was skipped.\n## forged heading"]),
                new ScanModule(
                    "failed",
                    "Failed analyzer",
                    AnalysisCategory.Security,
                    ModuleStatus.Failed,
                    now,
                    now,
                    0,
                    ErrorMessage: "Analyzer failed."),
                new ScanModule(
                    "skipped",
                    "Skipped analyzer",
                    AnalysisCategory.Codebase,
                    ModuleStatus.Skipped,
                    now,
                    now,
                    0,
                    SkippedReason: "Requires deep mode.")
            ]
        };

        var markdown = new MarkdownReportWriter().Write(scan);

        Assert.Contains("- Scan status: `CompletedWithWarnings`", markdown);
        Assert.Contains("- Completion: `1/3` modules completed", markdown);
        Assert.Contains("  - Warning: Cargo.lock was skipped. \\#\\# forged heading", markdown);
        Assert.Contains("  - Failure: Analyzer failed.", markdown);
        Assert.Contains("  - Skipped: Requires deep mode.", markdown);
        Assert.DoesNotContain("\n## forged heading", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void SarifReport_MapsFindingToSarifResult()
    {
        var finding = CreateFinding(
            "TRUST-VULN001",
            Severity.High,
            AnalysisCategory.Dependencies,
            evidenceKind: "vulnerability-advisory",
            filePath: "src/app.csproj",
            lineNumber: 7);
        var scan = CreateMinimalScan() with { Findings = [finding] };

        var sarif = new SarifReportWriter().Write(scan);

        using var document = JsonDocument.Parse(sarif);
        var root = document.RootElement;
        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.Equal("TRUST-VULN001", root.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("ruleId").GetString());
        Assert.Equal("error", root.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("level").GetString());
        Assert.Equal("src/app.csproj", root.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
        Assert.Matches("^[a-f0-9]{64}$", root.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("partialFingerprints").GetProperty("repoTrustDoctorFingerprint").GetString());
    }

    [Fact]
    public void SarifReport_DeduplicatesRules()
    {
        var scan = CreateMinimalScan() with
        {
            Findings =
            [
                CreateFinding("TRUST-GHA005", Severity.Medium, AnalysisCategory.CiCd),
                CreateFinding("TRUST-GHA005", Severity.Medium, AnalysisCategory.CiCd, lineNumber: 2)
            ]
        };

        var sarif = new SarifReportWriter().Write(scan);
        using var document = JsonDocument.Parse(sarif);
        var rules = document.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");

        Assert.Equal(1, rules.GetArrayLength());
    }

    [Fact]
    public void SarifReport_EmitsAllDistinctEvidenceLocations()
    {
        var finding = CreateFinding(
            "TRUST-GHA005",
            Severity.High,
            AnalysisCategory.CiCd,
            filePath: ".github/workflows/a.yml",
            lineNumber: 8);
        finding = finding with
        {
            Evidence =
            [
                .. finding.Evidence,
                new Evidence("workflow", "second occurrence", ".github/workflows/b.yml", 14),
                new Evidence("workflow", "duplicate occurrence", ".github/workflows/b.yml", 14),
                new Evidence("workflow", "no file location")
            ]
        };
        var scan = CreateMinimalScan() with { Findings = [finding] };

        using var document = JsonDocument.Parse(new SarifReportWriter().Write(scan));
        var locations = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("results")[0]
            .GetProperty("locations");

        Assert.Equal(2, locations.GetArrayLength());
        Assert.Equal(
            ".github/workflows/a.yml",
            locations[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
        Assert.Equal(
            ".github/workflows/b.yml",
            locations[1].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
    }

    [Fact]
    public void SarifReport_RuleDefaultSeverityUsesHighestOccurrenceRegardlessOfOrder()
    {
        var scan = CreateMinimalScan() with
        {
            Findings =
            [
                CreateFinding("TRUST-GHA005", Severity.Low, AnalysisCategory.CiCd),
                CreateFinding("TRUST-GHA005", Severity.High, AnalysisCategory.CiCd)
            ]
        };

        using var document = JsonDocument.Parse(new SarifReportWriter().Write(scan));
        var rule = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("tool")
            .GetProperty("driver")
            .GetProperty("rules")[0];

        Assert.Equal("High", rule.GetProperty("properties").GetProperty("defaultSeverity").GetString());
        Assert.Equal("error", rule.GetProperty("defaultConfiguration").GetProperty("level").GetString());
    }

    [Fact]
    public void SarifReport_HelpUriTargetsExistingRuleDocumentWithoutGuessedAnchor()
    {
        var scan = CreateMinimalScan() with
        {
            Findings = [CreateFinding("TRUST-GHA005", Severity.Medium, AnalysisCategory.CiCd)]
        };

        using var document = JsonDocument.Parse(new SarifReportWriter().Write(scan));
        var helpUri = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("tool")
            .GetProperty("driver")
            .GetProperty("rules")[0]
            .GetProperty("helpUri")
            .GetString();

        Assert.Equal(
            "https://github.com/Wezylnia/repo-trust-doctor/blob/main/docs/rules/github-actions.md",
            helpUri);
    }

    [Theory]
    [InlineData("TRUST-REPO002")]
    [InlineData("TRUST-WS001")]
    public void SarifReport_RepositoryRulesTargetRepositoryHealthDocumentation(string ruleId)
    {
        var scan = CreateMinimalScan() with
        {
            Findings = [CreateFinding(ruleId, Severity.Low, AnalysisCategory.RepositoryHealth)]
        };

        using var document = JsonDocument.Parse(new SarifReportWriter().Write(scan));
        var helpUri = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("tool")
            .GetProperty("driver")
            .GetProperty("rules")[0]
            .GetProperty("helpUri")
            .GetString();

        Assert.Equal(
            "https://github.com/Wezylnia/repo-trust-doctor/blob/main/docs/rules/repository-health.md",
            helpUri);
    }

    [Fact]
    public void SarifReport_DoesNotIncludeEvidenceValue()
    {
        var finding = CreateFinding(
            "TRUST-SECRET005",
            Severity.High,
            AnalysisCategory.Security,
            evidenceKind: "secret-pattern",
            filePath: "appsettings.json",
            evidenceValue: "postgres://user:raw-secret@example/db");
        var scan = CreateMinimalScan() with { Findings = [finding] };

        var sarif = new SarifReportWriter().Write(scan);

        Assert.DoesNotContain("raw-secret", sarif, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FindingFingerprint_DoesNotChangeWhenLineNumberChanges()
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

        Assert.Equal(FindingFingerprinter.Compute(first), FindingFingerprinter.Compute(second));
    }

    [Fact]
    public void FindingFingerprint_SeparatesDifferentTaggedEntitiesWithoutLocations()
    {
        var first = CreateFinding(
            "TRUST-VULN001",
            Severity.High,
            AnalysisCategory.Dependencies,
            evidenceKind: "vulnerability-advisory",
            message: "Package alpha matches advisory CVE-2026-0001.",
            evidenceMessage: "alpha@1.0.0 matches CVE-2026-0001.",
            tags: ["advisory:CVE-2026-0001"]);
        var second = CreateFinding(
            "TRUST-VULN001",
            Severity.High,
            AnalysisCategory.Dependencies,
            evidenceKind: "vulnerability-advisory",
            message: "Package beta matches advisory CVE-2026-0002.",
            evidenceMessage: "beta@2.0.0 matches CVE-2026-0002.",
            tags: ["advisory:CVE-2026-0002"]);

        Assert.NotEqual(FindingFingerprinter.Compute(first), FindingFingerprinter.Compute(second));
    }

    [Fact]
    public void FindingFingerprint_DisambiguatesStructurallyIdenticalFindingsInOneReport()
    {
        var first = CreateFinding(
            "TRUST-CODE015",
            Severity.High,
            AnalysisCategory.Codebase,
            evidenceKind: "command-execution",
            filePath: "src/process.cs",
            lineNumber: 12);
        var second = CreateFinding(
            "TRUST-CODE015",
            Severity.High,
            AnalysisCategory.Codebase,
            evidenceKind: "command-execution",
            filePath: "src/process.cs",
            lineNumber: 42);

        var fingerprinted = FindingFingerprinter.AddFingerprints([first, second]);

        Assert.Equal(2, fingerprinted.Select(finding => finding.Fingerprint).Distinct().Count());
        Assert.All(fingerprinted, finding => Assert.Matches("^[a-f0-9]{64}$", finding.Fingerprint));
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

    [Fact]
    public void FindingFingerprint_DoesNotChangeWhenFindingTextChanges()
    {
        var first = CreateFinding(
            "TRUST-GHA001",
            Severity.Medium,
            AnalysisCategory.CiCd,
            evidenceKind: "workflow-action",
            filePath: ".github/workflows/ci.yml",
            message: "Action was used 3 times.",
            evidenceMessage: "actions/cache@v4 was used 3 times.");
        var second = CreateFinding(
            "TRUST-GHA001",
            Severity.Medium,
            AnalysisCategory.CiCd,
            evidenceKind: "workflow-action",
            filePath: ".github/workflows/ci.yml",
            message: "Action was used 4 times.",
            evidenceMessage: "actions/cache@v4 was used 4 times.");

        Assert.Equal(
            FindingFingerprinter.Compute(first),
            FindingFingerprinter.Compute(second));
    }

    [Fact]
    public void FindingFingerprint_UsesIdentityKeyToSeparateLogicalEntities()
    {
        var first = CreateFinding(
            "TRUST-LIC003",
            Severity.Low,
            AnalysisCategory.Licenses) with
        {
            IdentityKey = "license|package:nuget:serilog|version:4.0.0"
        };
        var second = CreateFinding(
            "TRUST-LIC003",
            Severity.Low,
            AnalysisCategory.Licenses) with
        {
            IdentityKey = "license|package:nuget:nunit|version:4.0.0"
        };

        Assert.NotEqual(
            FindingFingerprinter.Compute(first),
            FindingFingerprinter.Compute(second));
    }

    [Fact]
    public void FindingFingerprint_IdentityKeyIgnoresPresentationFields()
    {
        var first = CreateFinding(
            "TRUST-VULN001",
            Severity.High,
            AnalysisCategory.Dependencies,
            title: "Old title",
            evidenceKind: "old-evidence",
            filePath: "old/path.json",
            recommendation: "Old recommendation.",
            tags: ["old-tag"]) with
        {
            IdentityKey = "vulnerability:nuget:serilog@4.0.0:GHSA-1234"
        };
        var second = CreateFinding(
            "TRUST-VULN001",
            Severity.High,
            AnalysisCategory.Dependencies,
            title: "New title",
            evidenceKind: "new-evidence",
            filePath: "new/path.json",
            recommendation: "New recommendation.",
            tags: ["new-tag"]) with
        {
            IdentityKey = "vulnerability:nuget:serilog@4.0.0:GHSA-1234"
        };

        Assert.Equal(
            FindingFingerprinter.Compute(first),
            FindingFingerprinter.Compute(second));
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
            ProductInfo.Version,
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
        string? evidenceValue = null,
        string? title = null,
        string? message = null,
        string? evidenceMessage = null,
        string? recommendation = null,
        IReadOnlyList<string>? tags = null)
    {
        return new Finding(
            ruleId,
            title ?? $"Title for {ruleId}",
            category,
            severity,
            Confidence.High,
            message ?? $"Message for {ruleId}",
            [new Evidence(evidenceKind, evidenceMessage ?? "test evidence", filePath, lineNumber, evidenceValue)],
            new Recommendation(recommendation ?? "Fix it."),
            isBlocking,
            Tags: tags);
    }
}

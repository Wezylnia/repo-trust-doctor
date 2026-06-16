using System.Globalization;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed class CoverageCriticalityAnalyzer : IRepositoryAnalyzer
{
    private const double MinimumCriticalLineCoverage = 0.60;

    public string Id => "codebase-03-coverage-criticality";

    public string DisplayName => "Critical Coverage Correlation";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => ["codebase-01-coverage-import", "codebase-02-criticality"];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE007",
            "Critical code has measured low coverage",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A critical source file has measured low line coverage.",
            "Add targeted tests around the critical code path."),
        new(
            "TRUST-CODE018",
            "Coverage is unknown for critical code",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A critical source file is absent from the imported coverage report.",
            "Ensure coverage reports include this source path, or document why coverage is intentionally unavailable.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        if (!context.TryGetArtifact<CoverageArtifact>(CoverageArtifact.ArtifactKey, out var coverage) ||
            !context.TryGetArtifact<CodeCriticalityArtifact>(CodeCriticalityArtifact.ArtifactKey, out var criticality) ||
            coverage is null ||
            criticality is null ||
            coverage.Reports.Count == 0 ||
            criticality.Files.Count == 0)
        {
            return Task.FromResult(AnalyzerResult.Completed([]));
        }

        var coverageByPath = coverage.Files
            .GroupBy(file => Normalize(file.FilePath), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var uniqueCoverageByFileName = coverage.Files
            .GroupBy(file => Path.GetFileName(Normalize(file.FilePath)), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);

        var matchedFindings = criticality.Files
            .Where(file => file.Score >= 50)
            .Select(file => CreateCoverageFinding(file, coverageByPath, uniqueCoverageByFileName))
            .Where(finding => finding is not null)
            .Cast<Finding>()
            .ToArray();
        var findings = matchedFindings.Take(10).ToArray();
        var suppressedCount = Math.Max(0, matchedFindings.Length - findings.Length);
        var metrics = new Dictionary<string, string>
        {
            ["code.coverage_criticality.finding.matched.count"] = matchedFindings.Length.ToString(CultureInfo.InvariantCulture),
            ["code.coverage_criticality.finding.reported.count"] = findings.Length.ToString(CultureInfo.InvariantCulture),
            ["code.coverage_criticality.finding.suppressed.count"] = suppressedCount.ToString(CultureInfo.InvariantCulture),
            ["code.coverage_criticality.finding.truncated"] = (suppressedCount > 0).ToString(CultureInfo.InvariantCulture)
        };
        var warnings = suppressedCount > 0
            ? new[]
            {
                $"Coverage criticality findings were truncated after {findings.Length.ToString(CultureInfo.InvariantCulture)} of {matchedFindings.Length.ToString(CultureInfo.InvariantCulture)} matches."
            }
            : [];

        return Task.FromResult(AnalyzerResult.Completed(findings, metrics: metrics, warnings: warnings));
    }

    private static Finding? CreateCoverageFinding(
        CodeCriticalityFile criticalFile,
        IReadOnlyDictionary<string, CoverageFileInfo> coverageByPath,
        IReadOnlyDictionary<string, CoverageFileInfo> uniqueCoverageByFileName)
    {
        var normalizedPath = Normalize(criticalFile.FilePath);
        var matchingCoverage = FindCoverage(
            normalizedPath,
            coverageByPath,
            uniqueCoverageByFileName);

        if (matchingCoverage is not null &&
            matchingCoverage.LineRate is double lineRate &&
            lineRate >= MinimumCriticalLineCoverage)
        {
            return null;
        }

        var isUnknown = matchingCoverage?.LineRate is null;
        var coverageText = isUnknown
            ? "unknown"
            : matchingCoverage!.LineRate!.Value.ToString("P0", CultureInfo.InvariantCulture);
        var message = $"{criticalFile.FilePath} is critical code with {coverageText} line coverage.";

        return new Finding(
            isUnknown ? "TRUST-CODE018" : "TRUST-CODE007",
            isUnknown ? "Coverage is unknown for critical code" : "Critical code has measured low coverage",
            AnalysisCategory.Codebase,
            isUnknown ? Severity.Medium : Severity.High,
            Confidence.Medium,
            message,
            [new Evidence("code.coverage_criticality", message, criticalFile.FilePath, criticalFile.FirstRelevantLine)],
            new Recommendation(isUnknown
                ? "Ensure the imported coverage report includes this critical source path, or review the path mapping."
                : "Add targeted unit or integration tests for the critical code path before relying on this repository in production."),
            Tags: ["codebase", "coverage", "criticality"]);
    }

    private static CoverageFileInfo? FindCoverage(
        string normalizedPath,
        IReadOnlyDictionary<string, CoverageFileInfo> coverageByPath,
        IReadOnlyDictionary<string, CoverageFileInfo> uniqueCoverageByFileName)
    {
        if (coverageByPath.TryGetValue(normalizedPath, out var exactMatch))
        {
            return exactMatch;
        }

        var suffixMatches = coverageByPath
            .Where(pair =>
                normalizedPath.EndsWith(pair.Key, StringComparison.OrdinalIgnoreCase) ||
                pair.Key.EndsWith(normalizedPath, StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (suffixMatches.Length == 1)
        {
            return suffixMatches[0].Value;
        }

        return suffixMatches.Length == 0
            ? uniqueCoverageByFileName.GetValueOrDefault(Path.GetFileName(normalizedPath))
            : null;
    }

    private static string Normalize(string path) => path.Replace('\\', '/').TrimStart('.', '/');
}

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
            "Critical code has low or missing coverage",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A critical source file has low line coverage or is absent from the imported coverage report.",
            "Add targeted tests around the critical code path, or document why coverage is intentionally unavailable.")
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

        var findings = criticality.Files
            .Where(file => file.Score >= 50)
            .Select(file => CreateCoverageFinding(file, coverageByPath))
            .Where(finding => finding is not null)
            .Cast<Finding>()
            .Take(10)
            .ToArray();

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }

    private static Finding? CreateCoverageFinding(CodeCriticalityFile criticalFile, IReadOnlyDictionary<string, CoverageFileInfo> coverageByPath)
    {
        var normalizedPath = Normalize(criticalFile.FilePath);
        var matchingCoverage = coverageByPath.TryGetValue(normalizedPath, out var exactMatch)
            ? exactMatch
            : coverageByPath
                .Where(pair => 
                    normalizedPath.EndsWith(pair.Key, StringComparison.OrdinalIgnoreCase) || 
                    pair.Key.EndsWith(normalizedPath, StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileName(normalizedPath).Equals(Path.GetFileName(pair.Key), StringComparison.OrdinalIgnoreCase))
                .Select(pair => pair.Value)
                .FirstOrDefault();

        if (matchingCoverage is not null &&
            matchingCoverage.LineRate is double lineRate &&
            lineRate >= MinimumCriticalLineCoverage)
        {
            return null;
        }

        var coverageText = matchingCoverage?.LineRate is double knownRate
            ? knownRate.ToString("P0", CultureInfo.InvariantCulture)
            : "missing";
        var message = $"{criticalFile.FilePath} is critical code with {coverageText} line coverage.";

        return new Finding(
            "TRUST-CODE007",
            "Critical code has low or missing coverage",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            message,
            [new Evidence("code.coverage_criticality", message, criticalFile.FilePath, criticalFile.FirstRelevantLine)],
            new Recommendation("Add targeted unit or integration tests for the critical code path before relying on this repository in production."),
            IsBlocking: true,
            Tags: ["codebase", "coverage", "criticality"]);
    }

    private static string Normalize(string path) => path.Replace('\\', '/').TrimStart('.', '/');
}

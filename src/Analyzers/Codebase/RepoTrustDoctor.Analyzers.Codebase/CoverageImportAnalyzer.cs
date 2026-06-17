using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed class CoverageImportAnalyzer : IRepositoryAnalyzer
{
    private const double MinimumLineCoverage = 0.70;

    public string Id => "codebase-01-coverage-import";

    public string DisplayName => "Coverage Report Import";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(15);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE001",
            "Coverage report was not found",
            AnalysisCategory.Codebase,
            Severity.Info,
            Confidence.High,
            "No supported coverage report was found during deep static analysis.",
            "Generate Cobertura XML or lcov coverage during CI and keep the artifact available to Repository Trust Doctor."),
        new(
            "TRUST-CODE002",
            "Imported coverage is below the recommended baseline",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A discovered coverage report indicates line coverage below the recommended baseline.",
            "Increase test coverage around changed and critical code paths, or document why the baseline is intentionally lower."),
        new(
            "TRUST-CODE003",
            "Coverage report could not be parsed",
            AnalysisCategory.Codebase,
            Severity.Low,
            Confidence.High,
            "A supported coverage report file was found but could not be parsed safely.",
            "Regenerate the coverage artifact in Cobertura XML or lcov format and ensure it is not truncated.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var reportFiles = FindCoverageReports(context.RepositoryPath).ToArray();
        var reports = new List<CoverageReportInfo>();
        var files = new List<CoverageFileInfo>();
        var findings = new List<Finding>();
        var warnings = new List<string>();

        foreach (var reportFile in reportFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var parsed = await ParseReportAsync(context.RepositoryPath, reportFile, cancellationToken);
                reports.Add(parsed.Report);
                files.AddRange(parsed.Files);
            }
            catch (Exception ex) when (ex is XmlException or InvalidDataException or IOException or UnauthorizedAccessException)
            {
                var relative = Path.GetRelativePath(context.RepositoryPath, reportFile);
                warnings.Add($"Could not parse coverage report '{relative}': {ex.Message}");
                findings.Add(CreateFinding(
                    "TRUST-CODE003",
                    Severity.Low,
                    "Coverage report could not be parsed",
                    $"The coverage report '{relative}' could not be parsed: {ex.Message}",
                    "coverage.parse_error",
                    relative));
            }
        }

        if (reports.Count == 0)
        {
            findings.Add(CreateFinding(
                "TRUST-CODE001",
                Severity.Info,
                "Coverage report was not found",
                "No Cobertura XML or lcov coverage report was found. Deep analysis will treat coverage as unknown instead of running tests.",
                "coverage.missing",
                null));
        }
        else
        {
            foreach (var report in reports.Where(report => report.LineRate is not null && report.LineRate < MinimumLineCoverage))
            {
                findings.Add(CreateFinding(
                    "TRUST-CODE002",
                    Severity.Medium,
                    "Imported coverage is below the recommended baseline",
                    $"Coverage report '{report.FilePath}' has {FormatPercent(report.LineRate!.Value)} line coverage.",
                    "coverage.low",
                    report.FilePath));
            }
        }

        var artifact = new CoverageArtifact(
            reports,
            files
                .GroupBy(file => file.FilePath, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.OrderByDescending(file => file.LineRate ?? -1).First())
                .OrderBy(file => file.FilePath, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            new Dictionary<string, string>
            {
                ["coverage.report.count"] = reports.Count.ToString(CultureInfo.InvariantCulture),
                ["coverage.file.count"] = files.Count.ToString(CultureInfo.InvariantCulture),
                ["coverage.average.line_rate"] = AverageRate(reports.Select(report => report.LineRate))
            });

        return AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(CoverageArtifact.ArtifactKey, artifact)],
            warnings: warnings,
            warningDetails: warnings.Select(warning => new ScanWarning(ScanWarningKind.UnsupportedInput, warning, AffectsCoverage: true)).ToArray());
    }

    private static IEnumerable<string> FindCoverageReports(string root)
    {
        foreach (var file in RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var fileName = Path.GetFileName(file);
            if (fileName.Equals("lcov.info", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("coverage.info", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("cobertura.xml", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("coverage.xml", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".cobertura.xml", StringComparison.OrdinalIgnoreCase))
            {
                yield return file;
            }
        }
    }

    private static async Task<ParsedCoverageReport> ParseReportAsync(string repositoryPath, string reportFile, CancellationToken cancellationToken)
    {
        var fileName = Path.GetFileName(reportFile);
        if (fileName.Equals("lcov.info", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("coverage.info", StringComparison.OrdinalIgnoreCase))
        {
            return await ParseLcovAsync(repositoryPath, reportFile, cancellationToken);
        }

        return ParseCobertura(repositoryPath, reportFile);
    }

    private static ParsedCoverageReport ParseCobertura(string repositoryPath, string reportFile)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        using var stream = File.OpenRead(reportFile);
        using var reader = XmlReader.Create(stream, settings);
        var document = XDocument.Load(reader, LoadOptions.None);
        var root = document.Root ?? throw new InvalidDataException("Coverage report does not contain a root element.");
        if (!root.Name.LocalName.Equals("coverage", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Coverage report root element is not 'coverage'.");
        }

        var report = new CoverageReportInfo(
            Path.GetRelativePath(repositoryPath, reportFile),
            CoverageReportFormat.Cobertura,
            ParseRate(root.Attribute("line-rate")?.Value),
            ParseRate(root.Attribute("branch-rate")?.Value),
            ParseInt(root.Attribute("lines-covered")?.Value),
            ParseInt(root.Attribute("lines-valid")?.Value),
            ParseInt(root.Attribute("branches-covered")?.Value),
            ParseInt(root.Attribute("branches-valid")?.Value));

        var files = root
            .Descendants()
            .Where(element => element.Name.LocalName.Equals("class", StringComparison.OrdinalIgnoreCase))
            .Select(element =>
            {
                var filePath = element.Attribute("filename")?.Value;
                if (string.IsNullOrWhiteSpace(filePath))
                {
                    return null;
                }

                return new CoverageFileInfo(
                    NormalizePath(repositoryPath, filePath),
                    ParseRate(element.Attribute("line-rate")?.Value),
                    ParseRate(element.Attribute("branch-rate")?.Value),
                    null,
                    null,
                    null,
                    null);
            })
            .Where(file => file is not null)
            .Cast<CoverageFileInfo>()
            .ToArray();

        return new ParsedCoverageReport(report, files);
    }

    private static async Task<ParsedCoverageReport> ParseLcovAsync(string repositoryPath, string reportFile, CancellationToken cancellationToken)
    {
        var files = new List<CoverageFileInfo>();
        string? currentFile = null;
        var lineHits = new List<int>();
        var branchHits = new List<int>();

        foreach (var line in await File.ReadAllLinesAsync(reportFile, cancellationToken))
        {
            if (line.StartsWith("SF:", StringComparison.Ordinal))
            {
                AddCurrentFile(files, currentFile, lineHits, branchHits);
                currentFile = NormalizePath(repositoryPath, line[3..].Trim());
                lineHits.Clear();
                branchHits.Clear();
                continue;
            }

            if (line.StartsWith("DA:", StringComparison.Ordinal))
            {
                var parts = line[3..].Split(',');
                if (parts.Length >= 2 && int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var hits))
                {
                    lineHits.Add(hits);
                }
                continue;
            }

            if (line.StartsWith("BRDA:", StringComparison.Ordinal))
            {
                var parts = line[5..].Split(',');
                if (parts.Length >= 4 && !parts[3].Equals("-", StringComparison.Ordinal))
                {
                    branchHits.Add(int.TryParse(parts[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var hits) ? hits : 0);
                }
                continue;
            }

            if (line.Equals("end_of_record", StringComparison.Ordinal))
            {
                AddCurrentFile(files, currentFile, lineHits, branchHits);
                currentFile = null;
                lineHits.Clear();
                branchHits.Clear();
            }
        }

        AddCurrentFile(files, currentFile, lineHits, branchHits);

        var coveredLines = files.Sum(file => file.CoveredLines ?? 0);
        var totalLines = files.Sum(file => file.TotalLines ?? 0);
        var coveredBranches = files.Sum(file => file.CoveredBranches ?? 0);
        var totalBranches = files.Sum(file => file.TotalBranches ?? 0);
        var report = new CoverageReportInfo(
            Path.GetRelativePath(repositoryPath, reportFile),
            CoverageReportFormat.Lcov,
            totalLines == 0 ? null : (double)coveredLines / totalLines,
            totalBranches == 0 ? null : (double)coveredBranches / totalBranches,
            coveredLines,
            totalLines,
            totalBranches == 0 ? null : coveredBranches,
            totalBranches == 0 ? null : totalBranches);

        return new ParsedCoverageReport(report, files);
    }

    private static void AddCurrentFile(List<CoverageFileInfo> files, string? currentFile, List<int> lineHits, List<int> branchHits)
    {
        if (string.IsNullOrWhiteSpace(currentFile))
        {
            return;
        }

        var coveredLines = lineHits.Count(hit => hit > 0);
        var totalLines = lineHits.Count;
        var coveredBranches = branchHits.Count(hit => hit > 0);
        var totalBranches = branchHits.Count;
        files.Add(new CoverageFileInfo(
            currentFile,
            totalLines == 0 ? null : (double)coveredLines / totalLines,
            totalBranches == 0 ? null : (double)coveredBranches / totalBranches,
            coveredLines,
            totalLines,
            totalBranches == 0 ? null : coveredBranches,
            totalBranches == 0 ? null : totalBranches));
    }

    private static Finding CreateFinding(string ruleId, Severity severity, string title, string message, string evidenceKind, string? filePath) =>
        new(
            ruleId,
            title,
            AnalysisCategory.Codebase,
            severity,
            Confidence.High,
            message,
            [new Evidence(evidenceKind, message, filePath)],
            new Recommendation("Publish Cobertura XML or lcov coverage artifacts from CI so trust analysis can reason about tested code paths."),
            Tags: ["coverage", "codebase"]);

    private static int? ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private static double? ParseRate(string? value) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private static string NormalizePath(string repositoryPath, string filePath)
    {
        var normalized = filePath.Replace('\\', '/');
        var repoNormalized = repositoryPath.Replace('\\', '/').TrimEnd('/') + '/';

        if (normalized.StartsWith(repoNormalized, StringComparison.OrdinalIgnoreCase))
        {
            return normalized[repoNormalized.Length..];
        }

        if (Path.IsPathRooted(filePath))
        {
            try
            {
                var relative = Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/');
                if (!relative.StartsWith("..", StringComparison.Ordinal))
                {
                    return relative;
                }
            }
            catch
            {
                // ignore
            }
        }

        return normalized.TrimStart('.', '/');
    }

    private static string FormatPercent(double rate) => rate.ToString("P0", CultureInfo.InvariantCulture);

    private static string AverageRate(IEnumerable<double?> rates)
    {
        var knownRates = rates.Where(rate => rate is not null).Select(rate => rate!.Value).ToArray();
        return knownRates.Length == 0
            ? "unknown"
            : knownRates.Average().ToString("0.###", CultureInfo.InvariantCulture);
    }

    private sealed record ParsedCoverageReport(CoverageReportInfo Report, IReadOnlyList<CoverageFileInfo> Files);
}

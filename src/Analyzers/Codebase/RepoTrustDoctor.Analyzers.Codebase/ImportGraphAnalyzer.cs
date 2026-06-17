using System.Globalization;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class ImportGraphAnalyzer : IRepositoryAnalyzer
{
    private const int CentralityThreshold = 10;
    private const double TopPercentile = 0.05;
    private const int MaxCentralFindings = 10;
    private const int MaxCoverageFindings = 8;
    private const int MaxAnalyzedSourceFiles = 6000;
    private const double LowCoverageThreshold = 0.60;

    private static readonly string[] SourceExtensions =
        [".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs"];

    public string Id => "codebase-05-import-graph";

    public string DisplayName => "Static Import Graph";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => [CoverageArtifact.ArtifactKey];

    public IReadOnlyCollection<string> ProducesArtifacts => [ImportGraphArtifact.ArtifactKey];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(30);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE010",
            "Highly central file detected",
            AnalysisCategory.Codebase,
            Severity.Info,
            Confidence.Medium,
            "A source file is imported by many other files, making it a high-impact change target.",
            "Ensure highly central files have thorough tests and careful review gates."),
        new(
            "TRUST-CODE011",
            "Central file has measured low coverage",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A highly central file has measured low test coverage, amplifying the blast radius of defects.",
            "Add targeted tests for central files to reduce risk of cascading breakage."),
        new(
            "TRUST-CODE019",
            "Coverage is unknown for central file",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "A highly central file is absent from the imported coverage report.",
            "Ensure coverage reports include central files, or review the path mapping.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var adjacency = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var inDegree = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var sourceFiles = EnumerateSourceFiles(context.RepositoryPath).ToArray();
        var selection = CodebaseFileSelection.Select(context.RepositoryPath, sourceFiles, MaxAnalyzedSourceFiles);
        var analyzedSourceFiles = selection.Files;
        var allFiles = analyzedSourceFiles
            .Select(file => ToRepoRelative(context.RepositoryPath, file))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var resolutionFiles = sourceFiles
            .Select(file => ToRepoRelative(context.RepositoryPath, file))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var fileIndex = new ImportGraphFileIndex(resolutionFiles, context.RepositoryPath, SourceExtensions);

        foreach (var file in analyzedSourceFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var relativePath = ToRepoRelative(context.RepositoryPath, file);

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var extension = Path.GetExtension(file).ToLowerInvariant();
            var imports = ParseImports(text, extension, relativePath, fileIndex);

            if (imports.Count > 0)
            {
                adjacency[relativePath] = imports;

                foreach (var imported in imports)
                {
                    inDegree.TryGetValue(imported, out var count);
                    inDegree[imported] = count + 1;
                }
            }
        }

        var importedByMap = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in adjacency)
        {
            foreach (var imported in kvp.Value)
            {
                if (!importedByMap.TryGetValue(imported, out var importers))
                {
                    importers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    importedByMap[imported] = importers;
                }

                importers.Add(kvp.Key);
            }
        }

        var centralFiles = IdentifyCentralFiles(inDegree, allFiles.Count, importedByMap);

        var findings = new List<Finding>();

        // TRUST-CODE010: highly central files
        foreach (var entry in centralFiles.Take(MaxCentralFindings))
        {
            findings.Add(new Finding(
                "TRUST-CODE010",
                "Highly central file detected",
                AnalysisCategory.Codebase,
                Severity.Info,
                Confidence.Medium,
                $"{entry.FilePath} is imported by {entry.InDegree.ToString(CultureInfo.InvariantCulture)} other files.",
                [new Evidence(
                    "import.centrality",
                    $"In-degree: {entry.InDegree.ToString(CultureInfo.InvariantCulture)}",
                    entry.FilePath)],
                new Recommendation("Ensure highly central files have thorough tests and careful review gates."),
                Tags: ["codebase", "import-graph", "centrality"]));
        }

        // TRUST-CODE011/019: central files with low or unknown coverage
        context.TryGetArtifact<CoverageArtifact>(CoverageArtifact.ArtifactKey, out var coverageArtifact);
        var coverageLookup = BuildCoverageLookup(coverageArtifact);

        if (coverageArtifact?.Reports.Count > 0)
        {
            var coverageFindingCount = 0;
            foreach (var entry in centralFiles)
            {
                if (coverageFindingCount >= MaxCoverageFindings)
                {
                    break;
                }

                if (TryFindCoverageRate(coverageLookup, entry.FilePath, out var rate))
                {
                    if (rate < LowCoverageThreshold)
                    {
                        var coverageMessage = $"{entry.FilePath} is imported by {entry.InDegree.ToString(CultureInfo.InvariantCulture)} files but has only {rate.ToString("P0", CultureInfo.InvariantCulture)} line coverage.";
                        findings.Add(CreateCoverageFinding(
                            "TRUST-CODE011",
                            "Central file has measured low coverage",
                            Severity.High,
                            entry.FilePath,
                            coverageMessage,
                            "Add targeted tests for central files to reduce risk of cascading breakage."));
                        coverageFindingCount++;
                    }
                    else
                    {
                        continue;
                    }
                }
                else
                {
                    var coverageMessage = $"{entry.FilePath} is imported by {entry.InDegree.ToString(CultureInfo.InvariantCulture)} files but has no matching coverage data.";
                    findings.Add(CreateCoverageFinding(
                        "TRUST-CODE019",
                        "Coverage is unknown for central file",
                        Severity.Medium,
                        entry.FilePath,
                        coverageMessage,
                        "Ensure imported coverage reports include this central source path, or review the path mapping."));
                    coverageFindingCount++;
                }
            }
        }

        var edges = adjacency.ToDictionary(
            kv => kv.Key,
            kv => (IReadOnlyList<string>)kv.Value,
            StringComparer.OrdinalIgnoreCase);

        var artifact = new ImportGraphArtifact(
            edges,
            centralFiles,
            new Dictionary<string, string>
            {
                ["import.graph.file.count"] = allFiles.Count.ToString(CultureInfo.InvariantCulture),
                ["import.graph.source_file.count"] = sourceFiles.Length.ToString(CultureInfo.InvariantCulture),
                ["import.graph.analyzed_file.count"] = analyzedSourceFiles.Count.ToString(CultureInfo.InvariantCulture),
                ["import.graph.truncated"] = (sourceFiles.Length > analyzedSourceFiles.Count).ToString(CultureInfo.InvariantCulture),
                ["import.graph.partition.count"] = selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture),
                ["import.graph.selected_partition.count"] = selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture),
                ["import.graph.edge.count"] = adjacency.Values.Sum(v => v.Count).ToString(CultureInfo.InvariantCulture),
                ["import.graph.central_file.count"] = centralFiles.Count.ToString(CultureInfo.InvariantCulture)
            });

        var warnings = sourceFiles.Length > analyzedSourceFiles.Count
            ? new[]
            {
                $"Import graph analyzed {analyzedSourceFiles.Count.ToString(CultureInfo.InvariantCulture)} of {sourceFiles.Length.ToString(CultureInfo.InvariantCulture)} source files, balanced across {selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture)} of {selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture)} repository partitions."
            }
            : [];

        return AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(ImportGraphArtifact.ArtifactKey, artifact)],
            warnings: warnings,
            warningDetails: warnings.Select(warning => new ScanWarning(ScanWarningKind.PartialCoverage, warning, AffectsCoverage: true)).ToArray());
    }

    private static Finding CreateCoverageFinding(
        string ruleId,
        string title,
        Severity severity,
        string filePath,
        string message,
        string recommendation) =>
        new(
            ruleId,
            title,
            AnalysisCategory.Codebase,
            severity,
            Confidence.Medium,
            message,
            [new Evidence("import.centrality.coverage", message, filePath)],
            new Recommendation(recommendation),
            Tags: ["codebase", "import-graph", "coverage"]);

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => SourceExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !IsLowSignalSource(root, file));

    private static bool IsLowSignalSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath);
    }

    private static string ToRepoRelative(string repositoryPath, string filePath) =>
        Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/');

    private static List<CentralFileEntry> IdentifyCentralFiles(
        Dictionary<string, int> inDegree,
        int totalFileCount,
        IReadOnlyDictionary<string, HashSet<string>> importedByMap)
    {
        if (inDegree.Count == 0)
        {
            return [];
        }

        // Determine threshold: in-degree >= 10 OR top 5%, whichever yields fewer files
        var sortedByDegree = inDegree
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var fixedThresholdFiles = sortedByDegree
            .Where(kv => kv.Value >= CentralityThreshold)
            .ToArray();

        var topPercentileCount = Math.Max(1, (int)(totalFileCount * TopPercentile));
        var topPercentileFiles = sortedByDegree
            .Take(topPercentileCount)
            .Where(kv => kv.Value >= 2) // Require at least 2 importers to be "central"
            .ToArray();

        // Use whichever set is smaller
        var centralSet = fixedThresholdFiles.Length <= topPercentileFiles.Length
            ? fixedThresholdFiles
            : topPercentileFiles;

        return centralSet
            .Select(kv =>
            {
                importedByMap.TryGetValue(kv.Key, out var list);
                return new CentralFileEntry(
                    kv.Key,
                    kv.Value,
                    list?.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray() ?? []);
            })
            .ToList();
    }

    private static Dictionary<string, double> BuildCoverageLookup(CoverageArtifact? coverageArtifact)
    {
        var lookup = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);

        if (coverageArtifact is null)
        {
            return lookup;
        }

        foreach (var file in coverageArtifact.Files)
        {
            if (file.LineRate.HasValue)
            {
                lookup[NormalizePath(file.FilePath)] = file.LineRate.Value;
            }
        }

        return lookup;
    }

    private static bool TryFindCoverageRate(
        IReadOnlyDictionary<string, double> coverageLookup,
        string filePath,
        out double rate)
    {
        var normalizedPath = NormalizePath(filePath);
        if (coverageLookup.TryGetValue(normalizedPath, out rate))
        {
            return true;
        }

        var matches = coverageLookup
            .Where(pair =>
                normalizedPath.EndsWith(pair.Key, StringComparison.OrdinalIgnoreCase) ||
                pair.Key.EndsWith(normalizedPath, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(normalizedPath).Equals(Path.GetFileName(pair.Key), StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (matches.Length == 1)
        {
            rate = matches[0].Value;
            return true;
        }

        rate = default;
        return false;
    }

    private static string NormalizePath(string path) => path.Replace('\\', '/').TrimStart('.', '/');

}

using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class ImportGraphAnalyzer : IRepositoryAnalyzer
{
    private const int CentralityThreshold = 10;
    private const double TopPercentile = 0.05;
    private const int MaxCentralFindings = 10;
    private const int MaxCoverageFindings = 8;
    private const double LowCoverageThreshold = 0.60;

    private static readonly string[] SourceExtensions =
        [".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs"];

    public string Id => "codebase-05-import-graph";

    public string DisplayName => "Static Import Graph";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => ["codebase-01-coverage-import"];

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
            "Central file has low or missing coverage",
            AnalysisCategory.Codebase,
            Severity.High,
            Confidence.Medium,
            "A highly central file has low or missing test coverage, amplifying the blast radius of defects.",
            "Add targeted tests for central files to reduce risk of cascading breakage.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var adjacency = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var inDegree = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var allFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in EnumerateSourceFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var relativePath = ToRepoRelative(context.RepositoryPath, file);
            allFiles.Add(relativePath);

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var extension = Path.GetExtension(file).ToLowerInvariant();
            var imports = ParseImports(text, extension, relativePath);

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

        var importedByMap = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in adjacency)
        {
            foreach (var imported in kvp.Value)
            {
                if (!importedByMap.TryGetValue(imported, out var list))
                {
                    list = new List<string>();
                    importedByMap[imported] = list;
                }
                list.Add(kvp.Key);
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

        // TRUST-CODE011: central files with low or missing coverage
        context.TryGetArtifact<CoverageArtifact>(CoverageArtifact.ArtifactKey, out var coverageArtifact);
        var coverageLookup = BuildCoverageLookup(coverageArtifact);

        var coverageFindingCount = 0;
        foreach (var entry in centralFiles)
        {
            if (coverageFindingCount >= MaxCoverageFindings)
            {
                break;
            }

            var hasLowCoverage = false;
            string coverageMessage;

            if (coverageLookup.TryGetValue(entry.FilePath, out var rate))
            {
                if (rate < LowCoverageThreshold)
                {
                    hasLowCoverage = true;
                    coverageMessage = $"{entry.FilePath} is imported by {entry.InDegree.ToString(CultureInfo.InvariantCulture)} files but has only {rate.ToString("P0", CultureInfo.InvariantCulture)} line coverage.";
                }
                else
                {
                    continue;
                }
            }
            else
            {
                hasLowCoverage = true;
                coverageMessage = $"{entry.FilePath} is imported by {entry.InDegree.ToString(CultureInfo.InvariantCulture)} files but has no coverage data.";
            }

            if (hasLowCoverage)
            {
                findings.Add(new Finding(
                    "TRUST-CODE011",
                    "Central file has low or missing coverage",
                    AnalysisCategory.Codebase,
                    Severity.High,
                    Confidence.Medium,
                    coverageMessage,
                    [new Evidence(
                        "import.centrality.coverage",
                        coverageMessage,
                        entry.FilePath)],
                    new Recommendation("Add targeted tests for central files to reduce risk of cascading breakage."),
                    Tags: ["codebase", "import-graph", "coverage"]));
                coverageFindingCount++;
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
                ["import.graph.edge.count"] = adjacency.Values.Sum(v => v.Count).ToString(CultureInfo.InvariantCulture),
                ["import.graph.central_file.count"] = centralFiles.Count.ToString(CultureInfo.InvariantCulture)
            });

        return AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(ImportGraphArtifact.ArtifactKey, artifact)]);
    }

    private static IEnumerable<string> EnumerateSourceFiles(string root) =>
        RepositoryFileSystem.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(file => SourceExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase));

    private static string ToRepoRelative(string repositoryPath, string filePath) =>
        Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/');

    private static List<string> ParseImports(string text, string extension, string sourceRelativePath)
    {
        var imports = new List<string>();

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();

            switch (extension)
            {
                case ".cs":
                    ParseCSharpImport(trimmed, imports);
                    break;
                case ".ts" or ".tsx" or ".js" or ".jsx":
                    ParseJavaScriptImport(trimmed, imports, sourceRelativePath);
                    break;
                case ".py":
                    ParsePythonImport(trimmed, imports);
                    break;
                case ".java":
                    ParseJavaImport(trimmed, imports);
                    break;
                case ".go":
                    ParseGoImport(trimmed, imports);
                    break;
                case ".rs":
                    ParseRustImport(trimmed, imports);
                    break;
            }
        }

        return imports;
    }

    private static void ParseCSharpImport(string line, List<string> imports)
    {
        // Skip: using var, using static, using System.*
        if (!line.StartsWith("using ", StringComparison.Ordinal))
        {
            return;
        }

        var match = CSharpUsingRegex().Match(line);
        if (!match.Success)
        {
            return;
        }

        var ns = match.Groups["ns"].Value;

        // Ignore system namespaces and directives
        if (ns.StartsWith("System", StringComparison.Ordinal) ||
            ns.StartsWith("Microsoft", StringComparison.Ordinal))
        {
            return;
        }

        imports.Add(ns);
    }

    private static void ParseJavaScriptImport(string line, List<string> imports, string sourceRelativePath)
    {
        Match? match = null;

        if (line.StartsWith("import", StringComparison.Ordinal))
        {
            match = JsImportFromRegex().Match(line);
            if (!match.Success)
            {
                match = JsDynamicImportRegex().Match(line);
            }
        }
        else if (line.Contains("require(", StringComparison.Ordinal))
        {
            match = JsRequireRegex().Match(line);
        }

        if (match is not { Success: true })
        {
            return;
        }

        var path = match.Groups["path"].Value;
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('.'))
        {
            // Only track relative imports
            return;
        }

        var resolved = ResolveRelativePath(sourceRelativePath, path);
        if (resolved is not null)
        {
            imports.Add(resolved);
        }
    }

    private static void ParsePythonImport(string line, List<string> imports)
    {
        if (line.StartsWith("from ", StringComparison.Ordinal))
        {
            var match = PythonFromImportRegex().Match(line);
            if (match.Success)
            {
                imports.Add(match.Groups["module"].Value);
            }
        }
        else if (line.StartsWith("import ", StringComparison.Ordinal))
        {
            var match = PythonImportRegex().Match(line);
            if (match.Success)
            {
                imports.Add(match.Groups["module"].Value);
            }
        }
    }

    private static void ParseJavaImport(string line, List<string> imports)
    {
        if (!line.StartsWith("import ", StringComparison.Ordinal))
        {
            return;
        }

        var match = JavaImportRegex().Match(line);
        if (match.Success)
        {
            imports.Add(match.Groups["pkg"].Value);
        }
    }

    private static void ParseGoImport(string line, List<string> imports)
    {
        var match = GoImportRegex().Match(line);
        if (match.Success)
        {
            imports.Add(match.Groups["path"].Value);
        }
    }

    private static void ParseRustImport(string line, List<string> imports)
    {
        if (line.StartsWith("use ", StringComparison.Ordinal))
        {
            var match = RustUseRegex().Match(line);
            if (match.Success)
            {
                imports.Add(match.Groups["path"].Value);
            }
        }
        else if (line.StartsWith("mod ", StringComparison.Ordinal))
        {
            var match = RustModRegex().Match(line);
            if (match.Success)
            {
                imports.Add(match.Groups["name"].Value);
            }
        }
    }

    private static string? ResolveRelativePath(string sourceRelativePath, string importPath)
    {
        var sourceDir = Path.GetDirectoryName(sourceRelativePath)?.Replace('\\', '/') ?? string.Empty;

        // Normalize the import path
        var combined = string.IsNullOrEmpty(sourceDir)
            ? importPath
            : $"{sourceDir}/{importPath}";

        // Simple normalization: resolve .. and .
        var parts = combined.Split('/');
        var stack = new Stack<string>();

        foreach (var part in parts)
        {
            if (part is "." or "")
            {
                continue;
            }

            if (part == "..")
            {
                if (stack.Count > 0)
                {
                    stack.Pop();
                }
            }
            else
            {
                stack.Push(part);
            }
        }

        if (stack.Count == 0)
        {
            return null;
        }

        return string.Join("/", stack.Reverse());
    }

    private static List<CentralFileEntry> IdentifyCentralFiles(
        Dictionary<string, int> inDegree,
        int totalFileCount,
        Dictionary<string, List<string>> importedByMap)
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
                return new CentralFileEntry(kv.Key, kv.Value, list ?? (IReadOnlyList<string>)Array.Empty<string>());
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
                lookup[file.FilePath] = file.LineRate.Value;
            }
        }

        return lookup;
    }

    // C#: using Namespace.Name;  (excludes using var, using static, using System.*)
    [GeneratedRegex(@"^using\s+(?!var\b)(?!static\b)(?<ns>[A-Za-z_][\w.]*)\s*;", RegexOptions.None)]
    private static partial Regex CSharpUsingRegex();

    // JS/TS: import ... from 'path' or import ... from "path"
    [GeneratedRegex(@"import\s+.*?\s+from\s+['""](?<path>[^'""]+)['""]", RegexOptions.None)]
    private static partial Regex JsImportFromRegex();

    // JS/TS: import('path')
    [GeneratedRegex(@"import\s*\(\s*['""](?<path>[^'""]+)['""]\s*\)", RegexOptions.None)]
    private static partial Regex JsDynamicImportRegex();

    // JS/TS: require('path')
    [GeneratedRegex(@"require\s*\(\s*['""](?<path>[^'""]+)['""]\s*\)", RegexOptions.None)]
    private static partial Regex JsRequireRegex();

    // Python: from module import ...
    [GeneratedRegex(@"^from\s+(?<module>[A-Za-z_][\w.]*)\s+import\b", RegexOptions.None)]
    private static partial Regex PythonFromImportRegex();

    // Python: import module
    [GeneratedRegex(@"^import\s+(?<module>[A-Za-z_][\w.]*)", RegexOptions.None)]
    private static partial Regex PythonImportRegex();

    // Java: import x.y.z;
    [GeneratedRegex(@"^import\s+(?:static\s+)?(?<pkg>[A-Za-z_][\w.]*)\s*;", RegexOptions.None)]
    private static partial Regex JavaImportRegex();

    // Go: "path" inside import block or single import
    [GeneratedRegex(@"""(?<path>[^""]+)""", RegexOptions.None)]
    private static partial Regex GoImportRegex();

    // Rust: use path::to::module;
    [GeneratedRegex(@"^use\s+(?<path>[A-Za-z_][\w:]*(?:::[A-Za-z_][\w:]*)*)", RegexOptions.None)]
    private static partial Regex RustUseRegex();

    // Rust: mod name;
    [GeneratedRegex(@"^mod\s+(?<name>[A-Za-z_]\w*)\s*;", RegexOptions.None)]
    private static partial Regex RustModRegex();
}

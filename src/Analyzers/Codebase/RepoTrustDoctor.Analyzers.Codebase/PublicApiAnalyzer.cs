using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class PublicApiAnalyzer : IRepositoryAnalyzer
{
    private const int MaxAnalyzedSourceFiles = 6000;
    private const long MaxBaselineBytes = 4L * 1024 * 1024;
    private readonly int maxAnalyzedSourceFiles;

    private static readonly string[] BaselinePaths =
    [
        Path.Combine(".repo-trust", "public-api-baseline.txt"),
        Path.Combine("docs", "public-api-baseline.txt"),
        "public-api-baseline.txt"
    ];

    public PublicApiAnalyzer()
        : this(MaxAnalyzedSourceFiles)
    {
    }

    internal PublicApiAnalyzer(int maxAnalyzedSourceFiles)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxAnalyzedSourceFiles);
        this.maxAnalyzedSourceFiles = maxAnalyzedSourceFiles;
    }

    public string Id => "codebase-04-public-api";

    public string DisplayName => "Public API Surface";

    public AnalysisCategory Category => AnalysisCategory.Codebase;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Deep;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(15);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new(
            "TRUST-CODE008",
            "Public API baseline is missing",
            AnalysisCategory.Codebase,
            Severity.Info,
            Confidence.Medium,
            "Public API symbols were detected, but no baseline file was found for conservative compatibility comparison.",
            "Commit a reviewed public API baseline when the repository exposes a library or reusable package."),
        new(
            "TRUST-CODE009",
            "Public API differs from baseline",
            AnalysisCategory.Codebase,
            Severity.Medium,
            Confidence.Medium,
            "The current public API symbol list differs from the committed baseline.",
            "Review added and removed symbols before release; removed symbols may be breaking changes for consumers.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var extensions = new[] { ".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs" };
        var sourceFiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*", SearchOption.AllDirectories)
            .Where(file => extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !IsLowSignalSource(context.RepositoryPath, file))
            .ToArray();
        var selection = CodebaseFileSelection.Select(context.RepositoryPath, sourceFiles, maxAnalyzedSourceFiles);
        var files = selection.Files;
        var unreadableSourceFileCount = 0;

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                unreadableSourceFileCount++;
                continue;
            }

            string text;
            try
            {
                text = await File.ReadAllTextAsync(file, cancellationToken);
            }
            catch (IOException)
            {
                unreadableSourceFileCount++;
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                unreadableSourceFileCount++;
                continue;
            }

            var ext = Path.GetExtension(file).ToLowerInvariant();
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file).Replace('\\', '/');
            var language = GetLanguageName(ext);

            IReadOnlyList<string> fileSymbols = ext switch
            {
                ".cs" => ExtractSymbols(text),
                ".ts" or ".tsx" or ".js" or ".jsx" => TypeScriptApiExtractor.ExtractSymbols(text),
                ".py" => PythonApiExtractor.ExtractSymbols(text),
                ".java" => JavaApiExtractor.ExtractSymbols(text),
                ".go" => GoApiExtractor.ExtractSymbols(text),
                ".rs" => RustApiExtractor.ExtractSymbols(text),
                _ => Array.Empty<string>()
            };

            foreach (var symbol in fileSymbols)
            {
                symbols.Add(QualifySymbol(language, relativePath, symbol));
            }
        }

        var baselineRead = await ReadBaselineAsync(context.RepositoryPath, cancellationToken);
        var baseline = baselineRead.Baseline;
        var sourceInventoryComplete =
            sourceFiles.Length == files.Count &&
            unreadableSourceFileCount == 0;
        var diffComparable = sourceInventoryComplete && baseline is not null;
        var added = Array.Empty<string>();
        var removed = Array.Empty<string>();
        var findings = new List<Finding>();

        if (symbols.Count > 0 && !baselineRead.Exists)
        {
            findings.Add(new Finding(
                "TRUST-CODE008",
                "Public API baseline is missing",
                AnalysisCategory.Codebase,
                Severity.Info,
                Confidence.Medium,
                $"Detected {symbols.Count.ToString(CultureInfo.InvariantCulture)} public API symbols but no baseline file.",
                [new Evidence("code.public_api_baseline", "No public API baseline file was found.")],
                new Recommendation("Add .repo-trust/public-api-baseline.txt for packages with a stable public API."),
                Tags: ["codebase", "public-api"]));
        }
        else if (diffComparable)
        {
            var comparisonSymbols = baseline!.IsLegacyFormat
                ? symbols.Select(UnqualifySymbol).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()
                : symbols.ToArray();
            added = comparisonSymbols.Except(baseline.Symbols, StringComparer.Ordinal).ToArray();
            removed = baseline.Symbols.Except(comparisonSymbols, StringComparer.Ordinal).ToArray();
            if (added.Length > 0 || removed.Length > 0)
            {
                findings.Add(new Finding(
                    "TRUST-CODE009",
                    "Public API differs from baseline",
                    AnalysisCategory.Codebase,
                    Severity.Medium,
                    Confidence.Medium,
                    $"Public API baseline differs: {added.Length.ToString(CultureInfo.InvariantCulture)} added, {removed.Length.ToString(CultureInfo.InvariantCulture)} removed.",
                    [new Evidence("code.public_api_diff", "Public API symbols differ from the committed baseline.", baseline.RelativePath)],
                    new Recommendation("Review the public API diff and update the baseline only after compatibility impact is understood."),
                    Tags: ["codebase", "public-api", "compatibility"]));
            }
        }

        var artifact = new CodePublicApiArtifact(
            symbols.ToArray(),
            baselineRead.RelativePath,
            added,
            removed,
            new Dictionary<string, string>
            {
                ["code.public_api.source_file.count"] = sourceFiles.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.analyzed_file.count"] = files.Count.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.unreadable_file.count"] = unreadableSourceFileCount.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.truncated"] = (sourceFiles.Length > files.Count).ToString(CultureInfo.InvariantCulture),
                ["code.public_api.inventory.complete"] = sourceInventoryComplete.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.partition.count"] = selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.selected_partition.count"] = selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.symbol.count"] = symbols.Count.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.added.count"] = added.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.removed.count"] = removed.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.baseline.present"] = baselineRead.Exists.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.baseline.readable"] = (baseline is not null).ToString(CultureInfo.InvariantCulture),
                ["code.public_api.baseline.format"] = baseline is null
                    ? "none"
                    : baseline.IsLegacyFormat ? "legacy" : "qualified",
                ["code.public_api.diff.comparable"] = diffComparable.ToString(CultureInfo.InvariantCulture)
            });

        var warnings = new List<string>();
        if (sourceFiles.Length > files.Count)
        {
            warnings.Add(
                $"Public API analysis processed {files.Count.ToString(CultureInfo.InvariantCulture)} of {sourceFiles.Length.ToString(CultureInfo.InvariantCulture)} source files, balanced across {selection.SelectedPartitionCount.ToString(CultureInfo.InvariantCulture)} of {selection.EligiblePartitionCount.ToString(CultureInfo.InvariantCulture)} repository partitions. Baseline comparison was skipped because the current API inventory is incomplete.");
        }

        if (unreadableSourceFileCount > 0)
        {
            warnings.Add(
                $"Public API analysis skipped {unreadableSourceFileCount.ToString(CultureInfo.InvariantCulture)} source files that exceeded the text safety limit or could not be read. Baseline comparison was skipped because the current API inventory is incomplete.");
        }

        if (baselineRead.Warning is not null)
        {
            warnings.Add(baselineRead.Warning);
        }

        return AnalyzerResult.Completed(
            findings,
            [new AnalyzerArtifact(CodePublicApiArtifact.ArtifactKey, artifact)],
            warnings: warnings,
            warningDetails: warnings.Select(warning => new ScanWarning(ScanWarningKind.PartialCoverage, warning, AffectsCoverage: true)).ToArray());
    }

    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var currentType = default(string);
        var currentTypeBraceDepth = 0;
        var awaitingTypeBrace = false;

        foreach (var rawLine in source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripInlineComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (currentType is not null && !awaitingTypeBrace && currentTypeBraceDepth <= 0)
            {
                currentType = null;
            }

            var typeMatch = TypeRegex().Match(line);
            if (typeMatch.Success)
            {
                currentType = typeMatch.Groups["name"].Value;
                symbols.Add($"type {currentType}");
                currentTypeBraceDepth = CountBraceDelta(line);
                awaitingTypeBrace = !line.Contains('{', StringComparison.Ordinal);
                if (!awaitingTypeBrace && currentTypeBraceDepth <= 0)
                {
                    currentType = null;
                }

                continue;
            }

            if (currentType is null)
            {
                continue;
            }

            if (awaitingTypeBrace)
            {
                if (line.Contains('{', StringComparison.Ordinal))
                {
                    awaitingTypeBrace = false;
                    currentTypeBraceDepth += CountBraceDelta(line);
                    if (currentTypeBraceDepth <= 0)
                    {
                        currentType = null;
                    }
                }

                continue;
            }

            var methodMatch = MethodRegex().Match(line);
            if (methodMatch.Success)
            {
                symbols.Add($"member {currentType}.{methodMatch.Groups["name"].Value}()");
            }
            else
            {
                var propertyMatch = PropertyRegex().Match(line);
                if (propertyMatch.Success)
                {
                    symbols.Add($"member {currentType}.{propertyMatch.Groups["name"].Value}");
                }
            }

            currentTypeBraceDepth += CountBraceDelta(line);
            if (currentTypeBraceDepth <= 0)
            {
                currentType = null;
            }
        }

        return symbols.ToArray();
    }

    private static int CountBraceDelta(string line) =>
        line.Count(static character => character == '{') -
        line.Count(static character => character == '}');

    private static bool IsLowSignalSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath);
    }

    private static string GetLanguageName(string extension) =>
        extension switch
        {
            ".cs" => "csharp",
            ".ts" or ".tsx" => "typescript",
            ".js" or ".jsx" => "javascript",
            ".py" => "python",
            ".java" => "java",
            ".go" => "go",
            ".rs" => "rust",
            _ => "unknown"
        };

    private static string QualifySymbol(string language, string relativePath, string symbol) =>
        $"{language}:{relativePath}:{symbol}";

    private static string UnqualifySymbol(string symbol)
    {
        var first = symbol.IndexOf(':');
        if (first < 0)
        {
            return symbol;
        }

        var second = symbol.IndexOf(':', first + 1);
        return second < 0 ? symbol : symbol[(second + 1)..];
    }

    private static async Task<BaselineReadResult> ReadBaselineAsync(
        string repositoryPath,
        CancellationToken cancellationToken)
    {
        foreach (var relativePath in BaselinePaths)
        {
            var fullPath = Path.Combine(repositoryPath, relativePath);
            if (!File.Exists(fullPath))
            {
                continue;
            }

            var normalizedPath = relativePath.Replace('\\', '/');
            if (!RepositoryFileSystem.CanReadAsText(fullPath, MaxBaselineBytes))
            {
                return new BaselineReadResult(
                    normalizedPath,
                    null,
                    $"Public API baseline '{normalizedPath}' exceeded the {MaxBaselineBytes / (1024 * 1024)} MiB safety limit or could not be read as text. Baseline comparison was skipped.");
            }

            try
            {
                var symbols = (await File.ReadAllLinesAsync(fullPath, cancellationToken))
                    .Select(line => line.Trim())
                    .Where(line => line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal))
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray();
                var isLegacyFormat = symbols.Any() && symbols.All(static symbol => !IsQualifiedSymbol(symbol));
                return new BaselineReadResult(
                    normalizedPath,
                    new ApiBaseline(normalizedPath, symbols, isLegacyFormat),
                    null);
            }
            catch (IOException)
            {
                return CreateUnreadableBaselineResult(normalizedPath);
            }
            catch (UnauthorizedAccessException)
            {
                return CreateUnreadableBaselineResult(normalizedPath);
            }
        }

        return new BaselineReadResult(null, null, null);
    }

    private static BaselineReadResult CreateUnreadableBaselineResult(string relativePath) =>
        new(
            relativePath,
            null,
            $"Public API baseline '{relativePath}' could not be read. Baseline comparison was skipped.");

    private static string StripInlineComment(string line)
    {
        var commentIndex = line.IndexOf("//", StringComparison.Ordinal);
        return commentIndex < 0 ? line : line[..commentIndex];
    }

    private static bool IsQualifiedSymbol(string symbol)
    {
        var first = symbol.IndexOf(':');
        if (first <= 0)
        {
            return false;
        }

        var second = symbol.IndexOf(':', first + 1);
        return second > first + 1 && second < symbol.Length - 1;
    }

    [GeneratedRegex(@"\bpublic\s+(?:sealed\s+|abstract\s+|static\s+|partial\s+)*(?:class|interface|record|struct)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\b")]
    private static partial Regex TypeRegex();

    [GeneratedRegex(@"\bpublic\s+(?:static\s+|virtual\s+|override\s+|abstract\s+|async\s+)*(?:[A-Za-z_][A-Za-z0-9_<>,\[\]\?\.]*\s+)+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")]
    private static partial Regex MethodRegex();

    [GeneratedRegex(@"\bpublic\s+(?:static\s+|virtual\s+|override\s+|abstract\s+)*(?:[A-Za-z_][A-Za-z0-9_<>,\[\]\?\.]*\s+)+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{\s*(?:get|init|set)\b")]
    private static partial Regex PropertyRegex();

    private sealed record ApiBaseline(string RelativePath, IReadOnlyList<string> Symbols, bool IsLegacyFormat);

    private sealed record BaselineReadResult(
        string? RelativePath,
        ApiBaseline? Baseline,
        string? Warning)
    {
        public bool Exists => RelativePath is not null;
    }
}

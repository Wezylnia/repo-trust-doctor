using System.Globalization;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Codebase;

public sealed partial class PublicApiAnalyzer : IRepositoryAnalyzer
{
    private const int MaxAnalyzedSourceFiles = 6000;

    private static readonly string[] BaselinePaths =
    [
        Path.Combine(".repo-trust", "public-api-baseline.txt"),
        Path.Combine("docs", "public-api-baseline.txt"),
        "public-api-baseline.txt"
    ];

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
            "The current public .NET API symbol list differs from the committed baseline.",
            "Review added and removed symbols before release; removed symbols may be breaking changes for consumers.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var extensions = new[] { ".cs", ".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs" };
        var sourceFiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*", SearchOption.AllDirectories)
            .Where(file => extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !IsLowSignalSource(context.RepositoryPath, file))
            .OrderBy(file => file, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var files = sourceFiles.Take(MaxAnalyzedSourceFiles).ToArray();

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var text = await File.ReadAllTextAsync(file, cancellationToken);
            var ext = Path.GetExtension(file).ToLowerInvariant();

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
                symbols.Add(symbol);
            }
        }

        var baseline = await ReadBaselineAsync(context.RepositoryPath, cancellationToken);
        var added = Array.Empty<string>();
        var removed = Array.Empty<string>();
        var findings = new List<Finding>();

        if (symbols.Count > 0 && baseline is null)
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
        else if (baseline is not null)
        {
            added = symbols.Except(baseline.Symbols, StringComparer.Ordinal).ToArray();
            removed = baseline.Symbols.Except(symbols, StringComparer.Ordinal).ToArray();
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
            baseline?.RelativePath,
            added,
            removed,
            new Dictionary<string, string>
            {
                ["code.public_api.source_file.count"] = sourceFiles.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.analyzed_file.count"] = files.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.truncated"] = (sourceFiles.Length > files.Length).ToString(CultureInfo.InvariantCulture),
                ["code.public_api.symbol.count"] = symbols.Count.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.added.count"] = added.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.removed.count"] = removed.Length.ToString(CultureInfo.InvariantCulture),
                ["code.public_api.baseline.present"] = (baseline is not null).ToString(CultureInfo.InvariantCulture)
            });

        var warnings = sourceFiles.Length > files.Length
            ? new[]
            {
                $"Public API analysis processed the first {files.Length.ToString(CultureInfo.InvariantCulture)} of {sourceFiles.Length.ToString(CultureInfo.InvariantCulture)} source files after low-signal filtering."
            }
            : [];

        return AnalyzerResult.Completed(findings, [new AnalyzerArtifact(CodePublicApiArtifact.ArtifactKey, artifact)], warnings: warnings);
    }

    public static IReadOnlyList<string> ExtractSymbols(string source)
    {
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var currentType = default(string);

        foreach (var rawLine in source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = StripInlineComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var typeMatch = TypeRegex().Match(line);
            if (typeMatch.Success)
            {
                currentType = typeMatch.Groups["name"].Value;
                symbols.Add($"type {currentType}");
                continue;
            }

            if (currentType is null)
            {
                continue;
            }

            var methodMatch = MethodRegex().Match(line);
            if (methodMatch.Success)
            {
                symbols.Add($"member {currentType}.{methodMatch.Groups["name"].Value}()");
                continue;
            }

            var propertyMatch = PropertyRegex().Match(line);
            if (propertyMatch.Success)
            {
                symbols.Add($"member {currentType}.{propertyMatch.Groups["name"].Value}");
            }
        }

        return symbols.ToArray();
    }

    private static bool IsLowSignalSource(string root, string filePath)
    {
        var relativePath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath);
    }

    private static async Task<ApiBaseline?> ReadBaselineAsync(string repositoryPath, CancellationToken cancellationToken)
    {
        foreach (var relativePath in BaselinePaths)
        {
            var fullPath = Path.Combine(repositoryPath, relativePath);
            if (!File.Exists(fullPath))
            {
                continue;
            }

            var symbols = (await File.ReadAllLinesAsync(fullPath, cancellationToken))
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            return new ApiBaseline(relativePath.Replace('\\', '/'), symbols);
        }

        return null;
    }

    private static string StripInlineComment(string line)
    {
        var commentIndex = line.IndexOf("//", StringComparison.Ordinal);
        return commentIndex < 0 ? line : line[..commentIndex];
    }

    [GeneratedRegex(@"\bpublic\s+(?:sealed\s+|abstract\s+|static\s+|partial\s+)*(?:class|interface|record|struct)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\b")]
    private static partial Regex TypeRegex();

    [GeneratedRegex(@"\bpublic\s+(?:static\s+|virtual\s+|override\s+|abstract\s+|async\s+)*(?:[A-Za-z_][A-Za-z0-9_<>,\[\]\?\.]*\s+)+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")]
    private static partial Regex MethodRegex();

    [GeneratedRegex(@"\bpublic\s+(?:static\s+|virtual\s+|override\s+|abstract\s+)*(?:[A-Za-z_][A-Za-z0-9_<>,\[\]\?\.]*\s+)+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{\s*(?:get|init|set)\b")]
    private static partial Regex PropertyRegex();

    private sealed record ApiBaseline(string RelativePath, IReadOnlyList<string> Symbols);
}

using System.Diagnostics;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Secrets;

public sealed class SecretQuickScanAnalyzer : IRepositoryAnalyzer
{
    private const int DefaultMaxSourceContentScanFiles = 800;
    private const int DefaultMaxConfigurationContentScanFiles = 1000;
    private const int StandardMaxSourceContentScanFiles = 2500;
    private const int StandardMaxConfigurationContentScanFiles = 2500;
    private const int DeepMaxSourceContentScanFiles = 10000;
    private const int DeepMaxConfigurationContentScanFiles = 5000;
    private const int MaxConcurrentContentScans = 8;
    private static readonly string[] SensitiveFileNames = [".env", ".env.local", ".env.production", ".env.development", "id_rsa", ".git-credentials", ".netrc"];
    private static readonly string[] CredentialConfigFileNames = [".npmrc", ".pypirc"];
    private static readonly string[] SensitiveExtensions = [".pem", ".key", ".ppk", ".p12", ".pfx"];
    private static readonly string[] SourceCodeExtensions =
    [
        ".cs", ".fs", ".vb",
        ".js", ".jsx", ".ts", ".tsx",
        ".py", ".go", ".java", ".kt", ".rs", ".rb", ".php", ".swift"
    ];

    private static readonly string[] CandidateTextExtensions =
    [
        .. SourceCodeExtensions,
        ".yml", ".yaml", ".json", ".toml", ".xml", ".props", ".targets",
        ".properties", ".ini", ".conf", ".config", ".cfg", ".txt",
        ".tf", ".tfvars", ".hcl",
        ".sh", ".bash", ".zsh", ".ps1", ".cmd", ".bat",
        ".gradle", ".kts"
    ];

    private readonly int maxSourceContentScanFiles;
    private readonly int maxConfigurationContentScanFiles;
    private readonly bool useDepthAdjustedBudgets;

    public SecretQuickScanAnalyzer()
        : this(
            DefaultMaxSourceContentScanFiles,
            DefaultMaxConfigurationContentScanFiles,
            useDepthAdjustedBudgets: true)
    {
    }

    public SecretQuickScanAnalyzer(int maxSourceContentScanFiles)
        : this(
            maxSourceContentScanFiles,
            DefaultMaxConfigurationContentScanFiles,
            useDepthAdjustedBudgets: false)
    {
    }

    public SecretQuickScanAnalyzer(int maxSourceContentScanFiles, int maxConfigurationContentScanFiles)
        : this(
            maxSourceContentScanFiles,
            maxConfigurationContentScanFiles,
            useDepthAdjustedBudgets: false)
    {
    }

    private SecretQuickScanAnalyzer(
        int maxSourceContentScanFiles,
        int maxConfigurationContentScanFiles,
        bool useDepthAdjustedBudgets)
    {
        this.maxSourceContentScanFiles = Math.Max(0, maxSourceContentScanFiles);
        this.maxConfigurationContentScanFiles = Math.Max(0, maxConfigurationContentScanFiles);
        this.useDepthAdjustedBudgets = useDepthAdjustedBudgets;
    }

    public string Id => "secret-quick-scan";

    public string DisplayName => "Secret Quick Scan";

    public AnalysisCategory Category => AnalysisCategory.Security;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(30);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-SECRET001", "Sensitive-looking file is committed", AnalysisCategory.Security, Severity.High, Confidence.High, "A sensitive-looking file was found in the repository.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET002", "Possible private key marker found", AnalysisCategory.Security, Severity.Critical, Confidence.High, "A private key block marker was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET003", "Possible GitHub token found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "A GitHub token-like value was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET004", "Possible AWS access key found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "An AWS access key-like value was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET005", "Possible database connection string found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "A connection string-like value was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET006", "Possible Slack webhook found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "A Slack webhook-like URL was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET007", "Possible Discord webhook found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "A Discord webhook-like URL was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET008", "Possible Azure connection string or storage key found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "An Azure connection string or storage account key was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET009", "Possible GCP service account key found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "A Google Cloud service account JSON key was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET010", "Possible JWT token found", AnalysisCategory.Security, Severity.Medium, Confidence.Medium, "A JWT-like token was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed. JWTs may grant access when valid."),
        new("TRUST-SECRET011", "Possible registry token found", AnalysisCategory.Security, Severity.High, Confidence.Medium, "An npm or PyPI registry token was found.", "Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
        new("TRUST-SECRET012", "Possible generic API key found", AnalysisCategory.Security, Severity.Medium, Confidence.Low, "A value matching a generic API key pattern was found.", "Manually verify whether the finding is a real secret, rotate if confirmed, and remove from repository history."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var selectedCandidates = new List<SecretCandidateFile>();
        var sourceContentScanned = 0;
        var sourceContentSkipped = 0;
        var configurationContentScanned = 0;
        var configurationContentSkipped = 0;
        var contentScanned = 0;
        var prefilterSkipped = 0;
        var candidateCount = 0;
        var sensitiveCandidateCount = 0;
        var selectionStopwatch = Stopwatch.StartNew();
        var (sourceLimit, configurationLimit) = GetContentBudgets(context.Depth);

        foreach (var candidate in EnumerateCandidateFiles(context.RepositoryPath)
                     .OrderBy(candidate => candidate.Kind)
                     .ThenBy(candidate => candidate.RelativePath, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            candidateCount++;
            if (candidate.Kind == SecretCandidateKind.Sensitive)
            {
                sensitiveCandidateCount++;
            }

            if (IsExampleFixturePath(candidate.RelativePath))
            {
                continue;
            }

            if (candidate.Kind == SecretCandidateKind.Sensitive &&
                !IsDocumentationSensitiveFilePath(candidate.RelativePath))
            {
                if (IsPublicCertificatePem(candidate.Path, candidate.Extension))
                {
                    continue;
                }

                findings.Add(SecretContentScanner.CreateSensitiveFileFinding(candidate));
            }

            if (candidate.Kind == SecretCandidateKind.Source &&
                sourceContentScanned >= sourceLimit)
            {
                sourceContentSkipped++;
                continue;
            }

            if (candidate.Kind == SecretCandidateKind.Configuration &&
                configurationContentScanned >= configurationLimit)
            {
                configurationContentSkipped++;
                continue;
            }

            if (candidate.Kind == SecretCandidateKind.Source)
            {
                sourceContentScanned++;
            }
            else if (candidate.Kind == SecretCandidateKind.Configuration)
            {
                configurationContentScanned++;
            }

            selectedCandidates.Add(candidate);
        }

        selectionStopwatch.Stop();
        var contentStopwatch = Stopwatch.StartNew();
        var scanResults = await ScanContentAsync(selectedCandidates, cancellationToken);
        contentStopwatch.Stop();
        foreach (var result in scanResults)
        {
            if (result.ContentRead)
            {
                contentScanned++;
            }

            if (result.PrefilterSkipped)
            {
                prefilterSkipped++;
            }

            findings.AddRange(result.Findings);
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["secret.candidate.count"] = candidateCount.ToString(),
            ["secret.sensitive.candidate.count"] = sensitiveCandidateCount.ToString(),
            ["secret.content.scanned.count"] = contentScanned.ToString(),
            ["secret.configuration.content.scanned.count"] = configurationContentScanned.ToString(),
            ["secret.configuration.content.skipped.count"] = configurationContentSkipped.ToString(),
            ["secret.source.content.scanned.count"] = sourceContentScanned.ToString(),
            ["secret.source.content.skipped.count"] = sourceContentSkipped.ToString(),
            ["secret.source.content.limit"] = sourceLimit.ToString(),
            ["secret.source.content.coverage.percent"] = CoveragePercent(sourceContentScanned, sourceContentSkipped),
            ["secret.configuration.content.limit"] = configurationLimit.ToString(),
            ["secret.configuration.content.coverage.percent"] = CoveragePercent(configurationContentScanned, configurationContentSkipped),
            ["secret.prefilter.skipped.count"] = prefilterSkipped.ToString(),
            ["secret.selection.elapsed.ms"] = selectionStopwatch.ElapsedMilliseconds.ToString(),
            ["secret.content.elapsed.ms"] = contentStopwatch.ElapsedMilliseconds.ToString(),
            ["secret.content.max.concurrency"] = MaxConcurrentContentScans.ToString()
        };
        var warnings = BuildBudgetWarnings(
            sourceContentScanned,
            sourceContentSkipped,
            configurationContentScanned,
            configurationContentSkipped);

        return AnalyzerResult.Completed(
            findings,
            metrics: metrics,
            warnings: warnings,
            warningDetails: warnings?.Select(warning => new ScanWarning(ScanWarningKind.PartialCoverage, warning, AffectsCoverage: true)).ToArray());
    }

    private (int Source, int Configuration) GetContentBudgets(AnalysisDepth depth)
    {
        if (!useDepthAdjustedBudgets)
        {
            return (maxSourceContentScanFiles, maxConfigurationContentScanFiles);
        }

        return depth switch
        {
            AnalysisDepth.Deep => (DeepMaxSourceContentScanFiles, DeepMaxConfigurationContentScanFiles),
            AnalysisDepth.Standard => (StandardMaxSourceContentScanFiles, StandardMaxConfigurationContentScanFiles),
            _ => (DefaultMaxSourceContentScanFiles, DefaultMaxConfigurationContentScanFiles)
        };
    }

    private static string CoveragePercent(int scanned, int skipped)
    {
        var total = scanned + skipped;
        if (total == 0)
        {
            return "100";
        }

        return (scanned * 100d / total)
            .ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<IReadOnlyList<SecretFileScanResult>> ScanContentAsync(
        IReadOnlyList<SecretCandidateFile> candidates,
        CancellationToken cancellationToken)
    {
        var results = new SecretFileScanResult?[candidates.Count];
        await Parallel.ForEachAsync(
            Enumerable.Range(0, candidates.Count),
            new ParallelOptions
            {
                MaxDegreeOfParallelism = MaxConcurrentContentScans,
                CancellationToken = cancellationToken
            },
            async (index, scanCancellationToken) =>
            {
                results[index] = await SecretContentScanner.ScanAsync(
                    candidates[index],
                    scanCancellationToken);
            });

        return results.Select(result => result!).ToArray();
    }

    private static IEnumerable<SecretCandidateFile> EnumerateCandidateFiles(string root)
    {
        foreach (var file in RepositoryFileSystem.EnumerateFiles(root))
        {
            var relativePath = Path.GetRelativePath(root, file).Replace('\\', '/');
            var fileName = Path.GetFileName(file);
            var extension = Path.GetExtension(file);
            if (RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath) &&
                !ShouldScanDocumentationContent(relativePath, fileName, extension))
            {
                continue;
            }

            var isSensitive = SensitiveFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) ||
                              SensitiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
            if (isSensitive)
            {
                yield return new SecretCandidateFile(file, relativePath, fileName, extension, SecretCandidateKind.Sensitive);
            }
            else if (CredentialConfigFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
            {
                yield return new SecretCandidateFile(file, relativePath, fileName, extension, SecretCandidateKind.CredentialConfiguration);
            }
            else if (CandidateTextExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) ||
                     IsDocumentationTextExtension(relativePath, extension))
            {
                yield return new SecretCandidateFile(
                    file,
                    relativePath,
                    fileName,
                    extension,
                    SourceCodeExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)
                        ? SecretCandidateKind.Source
                        : SecretCandidateKind.Configuration);
            }
        }
    }

    private static bool ShouldScanDocumentationContent(string relativePath, string fileName, string extension)
    {
        var classification = RepositoryPathClassifier.Classify(relativePath);
        const RepositoryPathClassification skippedDocumentationContexts =
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example |
            RepositoryPathClassification.Generated |
            RepositoryPathClassification.Template |
            RepositoryPathClassification.Benchmark |
            RepositoryPathClassification.Vendored;

        return classification.HasAny(RepositoryPathClassification.Documentation) &&
               !classification.HasAny(skippedDocumentationContexts) &&
               (CandidateTextExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) ||
                extension.Equals(".md", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".adoc", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".rst", StringComparison.OrdinalIgnoreCase) ||
                SensitiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) ||
                CredentialConfigFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsDocumentationTextExtension(string relativePath, string extension) =>
        RepositoryPathClassifier.IsDocumentationPath(relativePath) &&
        (extension.Equals(".md", StringComparison.OrdinalIgnoreCase) ||
         extension.Equals(".adoc", StringComparison.OrdinalIgnoreCase) ||
         extension.Equals(".rst", StringComparison.OrdinalIgnoreCase));

    private static string[]? BuildBudgetWarnings(
        int sourceContentScanned,
        int sourceContentSkipped,
        int configurationContentScanned,
        int configurationContentSkipped)
    {
        var warnings = new List<string>(capacity: 2);
        if (configurationContentSkipped > 0)
        {
            warnings.Add($"Secret quick scan skipped {configurationContentSkipped} lower-priority configuration files after scanning {configurationContentScanned} configuration files; sensitive filenames and credential config files were still analyzed.");
        }

        if (sourceContentSkipped > 0)
        {
            warnings.Add($"Secret quick scan skipped {sourceContentSkipped} lower-priority source files after scanning {sourceContentScanned} source files; sensitive filenames and credential config files were still analyzed.");
        }

        return warnings.Count > 0 ? warnings.ToArray() : null;
    }

    private static bool IsExampleFixturePath(string relativePath)
    {
        var classification = RepositoryPathClassifier.Classify(relativePath);
        const RepositoryPathClassification lowSignal =
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example;

        return classification.HasAny(lowSignal);
    }

    private static bool IsDocumentationSensitiveFilePath(string relativePath)
    {
        var normalized = RepositoryPathClassifier.Normalize(relativePath);
        var fileName = Path.GetFileName(normalized);
        var extension = Path.GetExtension(normalized);

        return RepositoryPathClassifier.IsDocumentationPath(normalized) &&
               (SensitiveFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) ||
                SensitiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsPublicCertificatePem(string filePath, string extension)
    {
        if (!extension.Equals(".pem", StringComparison.OrdinalIgnoreCase) ||
            !RepositoryFileSystem.CanReadAsText(filePath))
        {
            return false;
        }

        try
        {
            var content = File.ReadAllText(filePath);
            return content.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) &&
                   !SecretContentScanner.ContainsPrivateKeyMarker(content);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

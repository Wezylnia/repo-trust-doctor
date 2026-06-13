using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Secrets;

public sealed partial class SecretQuickScanAnalyzer : IRepositoryAnalyzer
{
    private const int DefaultMaxSourceContentScanFiles = 2500;
    private static readonly string[] SensitiveFileNames = [".env", ".env.local", ".env.production", ".env.development", ".npmrc", ".pypirc", "id_rsa", ".git-credentials", ".netrc"];
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

    public SecretQuickScanAnalyzer()
        : this(DefaultMaxSourceContentScanFiles)
    {
    }

    public SecretQuickScanAnalyzer(int maxSourceContentScanFiles)
    {
        this.maxSourceContentScanFiles = Math.Max(0, maxSourceContentScanFiles);
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
        var sourceContentScanned = 0;
        var sourceContentSkipped = 0;
        var contentScanned = 0;
        var prefilterSkipped = 0;
        var candidateCount = 0;
        var sensitiveCandidateCount = 0;

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

                findings.Add(CreateFinding("TRUST-SECRET001", "Sensitive-looking file is committed", Severity.High, Confidence.High, candidate.RelativePath, $"Sensitive-looking file '{candidate.FileName}' exists."));
            }

            if (!RepositoryFileSystem.CanReadAsText(candidate.Path))
            {
                continue;
            }

            if (candidate.Kind == SecretCandidateKind.Source &&
                sourceContentScanned >= maxSourceContentScanFiles)
            {
                sourceContentSkipped++;
                continue;
            }

            if (candidate.Kind == SecretCandidateKind.Source)
            {
                sourceContentScanned++;
            }

            var content = await TryReadTextAsync(candidate.Path, cancellationToken);
            if (content is null)
            {
                continue;
            }

            contentScanned++;
            if (!HasPotentialSecretSignal(content))
            {
                prefilterSkipped++;
                continue;
            }

            var privateKeyBlockMatch = PrivateKeyBlockPattern().Match(content);
            var privateKeyMarkerMatch = privateKeyBlockMatch.Success
                ? privateKeyBlockMatch
                : PrivateKeyMarkerPattern().Match(content);
            if (privateKeyMarkerMatch.Success &&
                !IsDocumentationTextPath(candidate.RelativePath) &&
                (privateKeyBlockMatch.Success
                    ? !IsLikelySourceCodePrivateKeyPattern(candidate.RelativePath, content, privateKeyBlockMatch)
                    : !IsLikelySourceCodeMarker(candidate.RelativePath, content, privateKeyMarkerMatch.Index)))
            {
                findings.Add(CreateFinding("TRUST-SECRET002", "Possible private key marker found", Severity.Critical, Confidence.High, candidate.RelativePath, "A private key block marker was found.", GetLineNumber(content, privateKeyMarkerMatch.Index), isBlocking: true));
            }

            if (GitHubTokenPattern().Match(content) is { Success: true } gitHubTokenMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET003", "Possible GitHub token found", Severity.High, Confidence.Medium, candidate.RelativePath, "A GitHub token-like value was found and redacted.", GetLineNumber(content, gitHubTokenMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(gitHubTokenMatch.Value)));
            }

            if (AwsAccessKeyPattern().Match(content) is { Success: true } awsAccessKeyMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET004", "Possible AWS access key found", Severity.High, Confidence.Medium, candidate.RelativePath, "An AWS access key-like value was found and redacted.", GetLineNumber(content, awsAccessKeyMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(awsAccessKeyMatch.Value)));
            }

            if (ConnectionStringPattern().Match(content) is { Success: true } connectionStringMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET005", "Possible database connection string found", Severity.High, Confidence.Medium, candidate.RelativePath, "A connection string-like value was found and redacted.", GetLineNumber(content, connectionStringMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(connectionStringMatch.Value)));
            }

            if (SlackWebhookPattern().Match(content) is { Success: true } slackWebhookMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET006", "Possible Slack webhook found", Severity.High, Confidence.Medium, candidate.RelativePath, "A Slack webhook-like URL was found.", GetLineNumber(content, slackWebhookMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(slackWebhookMatch.Value)));
            }

            if (DiscordWebhookPattern().Match(content) is { Success: true } discordWebhookMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET007", "Possible Discord webhook found", Severity.High, Confidence.Medium, candidate.RelativePath, "A Discord webhook-like URL was found.", GetLineNumber(content, discordWebhookMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(discordWebhookMatch.Value)));
            }

            if (AzureConnectionStringPattern().Match(content) is { Success: true } azureMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET008", "Possible Azure connection string or storage key found", Severity.High, Confidence.Medium, candidate.RelativePath, "An Azure connection string or storage account key was found and redacted.", GetLineNumber(content, azureMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(azureMatch.Value)));
            }

            if (GcpServiceAccountPattern().Match(content) is { Success: true } gcpMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET009", "Possible GCP service account key found", Severity.High, Confidence.Medium, candidate.RelativePath, "A Google Cloud service account JSON key was found.", GetLineNumber(content, gcpMatch.Index), isBlocking: true));
            }

            if (JwtTokenPattern().Match(content) is { Success: true } jwtMatch && !IsDocumentationMarkdownPath(candidate.RelativePath))
            {
                findings.Add(CreateFinding("TRUST-SECRET010", "Possible JWT token found", Severity.Medium, Confidence.Medium, candidate.RelativePath, "A JWT-like token was found and redacted.", GetLineNumber(content, jwtMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(jwtMatch.Value)));
            }

            if (RegistryTokenPattern().Match(content) is { Success: true } registryMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET011", "Possible registry token found", Severity.High, Confidence.Medium, candidate.RelativePath, "An npm or PyPI registry token was found and redacted.", GetLineNumber(content, registryMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(registryMatch.Value)));
            }

            if (GenericApiKeyPattern().Match(content) is { Success: true } apiKeyMatch)
            {
                var matchedValue = apiKeyMatch.Value;
                if (!IsPlaceholderValue(matchedValue) && IsGenericApiKeyStrength(matchedValue))
                {
                    findings.Add(CreateFinding("TRUST-SECRET012", "Possible generic API key found", Severity.Medium, Confidence.Low, candidate.RelativePath, "A value matching a generic API key pattern was found and redacted.", GetLineNumber(content, apiKeyMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(matchedValue)));
                }
            }
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["secret.candidate.count"] = candidateCount.ToString(),
            ["secret.sensitive.candidate.count"] = sensitiveCandidateCount.ToString(),
            ["secret.content.scanned.count"] = contentScanned.ToString(),
            ["secret.source.content.scanned.count"] = sourceContentScanned.ToString(),
            ["secret.source.content.skipped.count"] = sourceContentSkipped.ToString(),
            ["secret.prefilter.skipped.count"] = prefilterSkipped.ToString()
        };
        var warnings = sourceContentSkipped > 0
            ? new[]
            {
                $"Secret quick scan skipped {sourceContentSkipped} lower-priority source files after scanning {sourceContentScanned} source files; sensitive filenames and configuration files were still analyzed."
            }
            : null;

        return AnalyzerResult.Completed(findings, metrics: metrics, warnings: warnings);
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, Confidence confidence, string filePath, string evidence, int? lineNumber = null, bool isBlocking = false, string redactedValue = "[redacted]")
    {
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.Security,
            severity,
            confidence,
            title,
            [new Evidence("secret-pattern", evidence, filePath, lineNumber, redactedValue)],
            new Recommendation("Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
            isBlocking);
    }

    private static IEnumerable<SecretCandidateFile> EnumerateCandidateFiles(string root)
    {
        foreach (var file in RepositoryFileSystem.EnumerateFiles(root))
        {
            var relativePath = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath))
            {
                continue;
            }

            var fileName = Path.GetFileName(file);
            var extension = Path.GetExtension(file);
            var isSensitive = SensitiveFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) ||
                              SensitiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
            if (isSensitive)
            {
                yield return new SecretCandidateFile(file, relativePath, fileName, extension, SecretCandidateKind.Sensitive);
            }
            else if (CandidateTextExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
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

    private static async Task<string?> TryReadTextAsync(string file, CancellationToken cancellationToken)
    {
        try
        {
            return await File.ReadAllTextAsync(file, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool HasPotentialSecretSignal(string content) =>
        content.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("ghp_", StringComparison.Ordinal) ||
        content.Contains("gho_", StringComparison.Ordinal) ||
        content.Contains("ghu_", StringComparison.Ordinal) ||
        content.Contains("ghs_", StringComparison.Ordinal) ||
        content.Contains("ghr_", StringComparison.Ordinal) ||
        content.Contains("AKIA", StringComparison.Ordinal) ||
        content.Contains("hooks.slack.com/services/", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("discordapp.com/api/webhooks/", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("DefaultEndpointsProtocol=https", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("service_account", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("eyJ", StringComparison.Ordinal) ||
        content.Contains("npm_", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("pypi-", StringComparison.OrdinalIgnoreCase) ||
        HasConnectionStringSignal(content) ||
        HasGenericApiKeySignal(content);

    private static bool HasConnectionStringSignal(string content) =>
        content.Contains("password", StringComparison.OrdinalIgnoreCase) &&
        (content.Contains("server", StringComparison.OrdinalIgnoreCase) ||
         content.Contains("host", StringComparison.OrdinalIgnoreCase) ||
         content.Contains("data source", StringComparison.OrdinalIgnoreCase) ||
         content.Contains("user id", StringComparison.OrdinalIgnoreCase) ||
         content.Contains("username", StringComparison.OrdinalIgnoreCase) ||
         content.Contains("uid", StringComparison.OrdinalIgnoreCase));

    private static bool HasGenericApiKeySignal(string content) =>
        content.Contains("api_key", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("api-key", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("apiSecret", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("api_secret", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("api-secret", StringComparison.OrdinalIgnoreCase) ||
        content.Contains("apikey", StringComparison.OrdinalIgnoreCase);

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var index = 0; index < matchIndex && index < content.Length; index++)
        {
            if (content[index] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    private static bool IsExampleFixturePath(string relativePath)
    {
        return RepositoryPathClassifier.IsTestFixtureExampleOrDocumentationPath(relativePath);
    }

    private static bool IsDocumentationMarkdownPath(string relativePath)
    {
        var normalized = RepositoryPathClassifier.Normalize(relativePath);
        return normalized.EndsWith(".md", StringComparison.OrdinalIgnoreCase) &&
               RepositoryPathClassifier.IsDocumentationPath(normalized);
    }

    private static bool IsDocumentationTextPath(string relativePath)
    {
        var normalized = RepositoryPathClassifier.Normalize(relativePath);
        var isDocumentationFile = normalized.EndsWith(".md", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".adoc", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".rst", StringComparison.OrdinalIgnoreCase) ||
                                  normalized.EndsWith(".txt", StringComparison.OrdinalIgnoreCase);

        return isDocumentationFile && RepositoryPathClassifier.IsDocumentationPath(normalized);
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
                   !PrivateKeyMarkerPattern().IsMatch(content);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsLikelySourceCodeMarker(string relativePath, string content, int matchIndex)
    {
        if (!IsSourceCodePath(relativePath))
        {
            return false;
        }

        var lineStart = content.LastIndexOf('\n', Math.Max(0, matchIndex - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var lineEnd = content.IndexOf('\n', matchIndex);
        lineEnd = lineEnd < 0 ? content.Length : lineEnd;
        var line = content[lineStart..lineEnd].Trim();

        return line.StartsWith("//", StringComparison.Ordinal) ||
               line.StartsWith("#", StringComparison.Ordinal) ||
               line.StartsWith("*", StringComparison.Ordinal) ||
               line.Contains('"', StringComparison.Ordinal) ||
               line.Contains('\'', StringComparison.Ordinal) ||
               line.Contains('`', StringComparison.Ordinal);
    }

    private static bool IsLikelySourceCodePrivateKeyPattern(string relativePath, string content, Match match)
    {
        if (!IsSourceCodePath(relativePath))
        {
            return false;
        }

        var matchedText = match.Value;
        if (matchedText.Contains(@"[\s\S]", StringComparison.Ordinal) ||
            matchedText.Contains(@"\s", StringComparison.Ordinal) ||
            matchedText.Contains(".+?", StringComparison.Ordinal) ||
            matchedText.Contains(".*?", StringComparison.Ordinal))
        {
            return true;
        }

        return false;
    }

    private static bool IsSourceCodePath(string relativePath)
    {
        var extension = Path.GetExtension(relativePath);
        return extension.Equals(".cs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ts", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".tsx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".jsx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".java", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".go", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".py", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".rs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".kt", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".swift", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".php", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".rb", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPlaceholderValue(string value)
    {
        var lower = value.ToLowerInvariant();

        // Skip variable references
        if (lower.Contains("${{", StringComparison.Ordinal) ||
            lower.Contains("${", StringComparison.Ordinal) ||
            lower.Contains("%", StringComparison.Ordinal))
            return true;

        // Skip known placeholder tokens
        return lower.Contains("your-api-key", StringComparison.Ordinal) ||
               lower.Contains("example-token", StringComparison.Ordinal) ||
               lower.Contains("example", StringComparison.Ordinal) ||
               lower.Contains("test-token", StringComparison.Ordinal) ||
               lower.Contains("dummy-secret", StringComparison.Ordinal) ||
               lower.Contains("dummy", StringComparison.Ordinal) ||
               lower.Contains("changeme", StringComparison.Ordinal) ||
               lower.Contains("placeholder", StringComparison.Ordinal) ||
               lower.Contains("replace", StringComparison.Ordinal) ||
               lower.Contains("sample", StringComparison.Ordinal) ||
               lower.Contains("xxxx", StringComparison.Ordinal) ||
               lower.Contains("abc123", StringComparison.Ordinal) ||
               lower.Contains("sample-key", StringComparison.Ordinal) ||
               lower.Contains("your-secret", StringComparison.Ordinal) ||
               lower.Contains("replace-me", StringComparison.Ordinal) ||
               lower.Contains("test", StringComparison.Ordinal);
    }

    private static bool IsGenericApiKeyStrength(string value)
    {
        // Strip surrounding quotes
        var trimmed = value.Trim('"', '\'', '`').Trim();

        // Must be at least 20 meaningful characters
        var alphanumeric = trimmed.Count(char.IsLetterOrDigit);
        if (alphanumeric < 20)
            return false;

        // Must have at least one uppercase, one lowercase, one digit
        var hasUpper = false;
        var hasLower = false;
        var hasDigit = false;
        foreach (var c in trimmed)
        {
            if (char.IsUpper(c)) hasUpper = true;
            if (char.IsLower(c)) hasLower = true;
            if (char.IsDigit(c)) hasDigit = true;
            if (hasUpper && hasLower && hasDigit)
                return true;
        }

        return false;
    }

    private sealed record SecretCandidateFile(
        string Path,
        string RelativePath,
        string FileName,
        string Extension,
        SecretCandidateKind Kind);

    private enum SecretCandidateKind
    {
        Sensitive = 0,
        Configuration = 1,
        Source = 2
    }

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyBlockPattern();

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyMarkerPattern();

    [GeneratedRegex(@"gh[pousr]_[A-Za-z0-9_]{20,}")]
    private static partial Regex GitHubTokenPattern();

    [GeneratedRegex(@"AKIA[0-9A-Z]{16}")]
    private static partial Regex AwsAccessKeyPattern();

    [GeneratedRegex(@"(?i)(Server|Host|Data Source)\s*=.+;(User Id|Username|Uid)\s*=.+;(Password|Pwd)\s*=")]
    private static partial Regex ConnectionStringPattern();

    [GeneratedRegex(@"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+")]
    private static partial Regex SlackWebhookPattern();

    [GeneratedRegex(@"https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_/]+")]
    private static partial Regex DiscordWebhookPattern();

    [GeneratedRegex(@"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+")]
    private static partial Regex AzureConnectionStringPattern();

    [GeneratedRegex(@"""type""\s*:\s*""service_account""")]
    private static partial Regex GcpServiceAccountPattern();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")]
    private static partial Regex JwtTokenPattern();

    [GeneratedRegex(@"(?i)(npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9]+)")]
    private static partial Regex RegistryTokenPattern();

    [GeneratedRegex(@"(?i)(api[_-]?key|api[_-]?secret|apikey)\s*[:=]\s*['""]?[A-Za-z0-9_\-]{16,}['""]?")]
    private static partial Regex GenericApiKeyPattern();
}

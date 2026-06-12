using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Secrets;

public sealed partial class SecretQuickScanAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] SensitiveFileNames = [".env", ".env.production", "id_rsa", ".git-credentials", ".netrc"];
    private static readonly string[] SensitiveExtensions = [".pem", ".key", ".ppk", ".p12", ".pfx"];

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

        foreach (var file in EnumerateCandidateFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);
            var fileName = Path.GetFileName(file);
            var extension = Path.GetExtension(file);

            if (IsExampleFixturePath(relativePath))
            {
                continue;
            }

            if (SensitiveFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) || SensitiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
            {
                findings.Add(CreateFinding("TRUST-SECRET001", "Sensitive-looking file is committed", Severity.High, Confidence.High, relativePath, $"Sensitive-looking file '{fileName}' exists."));
                continue;
            }

            if (!RepositoryFileSystem.CanReadAsText(file))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            if (PrivateKeyPattern().Match(content) is { Success: true } privateKeyMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET002", "Possible private key marker found", Severity.Critical, Confidence.High, relativePath, "A private key block marker was found.", GetLineNumber(content, privateKeyMatch.Index), isBlocking: true));
            }

            if (GitHubTokenPattern().Match(content) is { Success: true } gitHubTokenMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET003", "Possible GitHub token found", Severity.High, Confidence.Medium, relativePath, "A GitHub token-like value was found and redacted.", GetLineNumber(content, gitHubTokenMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(gitHubTokenMatch.Value)));
            }

            if (AwsAccessKeyPattern().Match(content) is { Success: true } awsAccessKeyMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET004", "Possible AWS access key found", Severity.High, Confidence.Medium, relativePath, "An AWS access key-like value was found and redacted.", GetLineNumber(content, awsAccessKeyMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(awsAccessKeyMatch.Value)));
            }

            if (ConnectionStringPattern().Match(content) is { Success: true } connectionStringMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET005", "Possible database connection string found", Severity.High, Confidence.Medium, relativePath, "A connection string-like value was found and redacted.", GetLineNumber(content, connectionStringMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(connectionStringMatch.Value)));
            }

            if (SlackWebhookPattern().Match(content) is { Success: true } slackWebhookMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET006", "Possible Slack webhook found", Severity.High, Confidence.Medium, relativePath, "A Slack webhook-like URL was found.", GetLineNumber(content, slackWebhookMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(slackWebhookMatch.Value)));
            }

            if (DiscordWebhookPattern().Match(content) is { Success: true } discordWebhookMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET007", "Possible Discord webhook found", Severity.High, Confidence.Medium, relativePath, "A Discord webhook-like URL was found.", GetLineNumber(content, discordWebhookMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(discordWebhookMatch.Value)));
            }

            if (AzureConnectionStringPattern().Match(content) is { Success: true } azureMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET008", "Possible Azure connection string or storage key found", Severity.High, Confidence.Medium, relativePath, "An Azure connection string or storage account key was found and redacted.", GetLineNumber(content, azureMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(azureMatch.Value)));
            }

            if (GcpServiceAccountPattern().Match(content) is { Success: true } gcpMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET009", "Possible GCP service account key found", Severity.High, Confidence.Medium, relativePath, "A Google Cloud service account JSON key was found.", GetLineNumber(content, gcpMatch.Index), isBlocking: true));
            }

            if (JwtTokenPattern().Match(content) is { Success: true } jwtMatch && !IsDocumentationMarkdownPath(relativePath))
            {
                findings.Add(CreateFinding("TRUST-SECRET010", "Possible JWT token found", Severity.Medium, Confidence.Medium, relativePath, "A JWT-like token was found and redacted.", GetLineNumber(content, jwtMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(jwtMatch.Value)));
            }

            if (RegistryTokenPattern().Match(content) is { Success: true } registryMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET011", "Possible registry token found", Severity.High, Confidence.Medium, relativePath, "An npm or PyPI registry token was found and redacted.", GetLineNumber(content, registryMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(registryMatch.Value)));
            }

            if (GenericApiKeyPattern().Match(content) is { Success: true } apiKeyMatch)
            {
                var matchedValue = apiKeyMatch.Value;
                if (!IsPlaceholderValue(matchedValue) && IsGenericApiKeyStrength(matchedValue))
                {
                    findings.Add(CreateFinding("TRUST-SECRET012", "Possible generic API key found", Severity.Medium, Confidence.Low, relativePath, "A value matching a generic API key pattern was found and redacted.", GetLineNumber(content, apiKeyMatch.Index), redactedValue: SecretEvidenceRedactor.Redact(matchedValue)));
                }
            }
        }

        return AnalyzerResult.Completed(findings);
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

    private static IEnumerable<string> EnumerateCandidateFiles(string root)
    {
        return RepositoryFileSystem.EnumerateFiles(root);
    }

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
        var normalized = relativePath.Replace('\\', '/');
        return normalized.Contains("tests/Fixtures/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/__tests__/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("__tests__/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("fixtures/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/TestFiles/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("TestFiles/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/examples/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("examples/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/playground/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("playground/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("testdata/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("docs/examples/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDocumentationMarkdownPath(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');
        return normalized.EndsWith(".md", StringComparison.OrdinalIgnoreCase) &&
               (normalized.StartsWith("docs/", StringComparison.OrdinalIgnoreCase) ||
                normalized.Contains("/docs/", StringComparison.OrdinalIgnoreCase));
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

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyPattern();

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

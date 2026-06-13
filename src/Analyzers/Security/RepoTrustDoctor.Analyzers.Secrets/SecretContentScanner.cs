using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Secrets;

internal sealed record SecretCandidateFile(
    string Path,
    string RelativePath,
    string FileName,
    string Extension,
    SecretCandidateKind Kind);

internal enum SecretCandidateKind
{
    Sensitive = 0,
    CredentialConfiguration = 1,
    Configuration = 2,
    Source = 3
}

internal sealed record SecretFileScanResult(
    bool ContentRead,
    bool PrefilterSkipped,
    IReadOnlyList<Finding> Findings);

internal static partial class SecretContentScanner
{
    public static async Task<SecretFileScanResult> ScanAsync(
        SecretCandidateFile candidate,
        CancellationToken cancellationToken)
    {
        if (!RepositoryFileSystem.CanReadAsText(candidate.Path))
        {
            return new SecretFileScanResult(false, false, []);
        }

        string content;
        try
        {
            content = await File.ReadAllTextAsync(candidate.Path, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new SecretFileScanResult(false, false, []);
        }

        if (!HasPotentialSecretSignal(content))
        {
            return new SecretFileScanResult(true, true, []);
        }

        return new SecretFileScanResult(
            true,
            false,
            ScanContent(candidate.RelativePath, content));
    }

    public static Finding CreateSensitiveFileFinding(SecretCandidateFile candidate) =>
        CreateFinding(
            "TRUST-SECRET001",
            "Sensitive-looking file is committed",
            Severity.High,
            Confidence.High,
            candidate.RelativePath,
            $"Sensitive-looking file '{candidate.FileName}' exists.");

    public static bool ContainsPrivateKeyMarker(string content) =>
        PrivateKeyMarkerPattern().IsMatch(content);

    private static IReadOnlyList<Finding> ScanContent(
        string relativePath,
        string content)
    {
        var findings = new List<Finding>();
        var privateKeyBlockMatch = PrivateKeyBlockPattern().Match(content);
        var privateKeyMarkerMatch = privateKeyBlockMatch.Success
            ? privateKeyBlockMatch
            : PrivateKeyMarkerPattern().Match(content);
        if (privateKeyMarkerMatch.Success &&
            !IsDocumentationTextPath(relativePath) &&
            (privateKeyBlockMatch.Success
                ? !IsLikelySourceCodePrivateKeyPattern(relativePath, privateKeyBlockMatch)
                : !IsLikelySourceCodeMarker(relativePath, content, privateKeyMarkerMatch.Index)))
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET002",
                "Possible private key marker found",
                Severity.Critical,
                Confidence.High,
                relativePath,
                "A private key block marker was found.",
                GetLineNumber(content, privateKeyMarkerMatch.Index),
                isBlocking: true));
        }

        if (GitHubTokenPattern().Match(content) is { Success: true } gitHubTokenMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET003",
                "Possible GitHub token found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A GitHub token-like value was found and redacted.",
                GetLineNumber(content, gitHubTokenMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(gitHubTokenMatch.Value)));
        }

        if (AwsAccessKeyPattern().Match(content) is { Success: true } awsAccessKeyMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET004",
                "Possible AWS access key found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "An AWS access key-like value was found and redacted.",
                GetLineNumber(content, awsAccessKeyMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(awsAccessKeyMatch.Value)));
        }

        if (ConnectionStringPattern().Match(content) is { Success: true } connectionStringMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET005",
                "Possible database connection string found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A connection string-like value was found and redacted.",
                GetLineNumber(content, connectionStringMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(connectionStringMatch.Value)));
        }

        if (SlackWebhookPattern().Match(content) is { Success: true } slackWebhookMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET006",
                "Possible Slack webhook found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A Slack webhook-like URL was found.",
                GetLineNumber(content, slackWebhookMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(slackWebhookMatch.Value)));
        }

        if (DiscordWebhookPattern().Match(content) is { Success: true } discordWebhookMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET007",
                "Possible Discord webhook found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A Discord webhook-like URL was found.",
                GetLineNumber(content, discordWebhookMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(discordWebhookMatch.Value)));
        }

        if (AzureConnectionStringPattern().Match(content) is { Success: true } azureMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET008",
                "Possible Azure connection string or storage key found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "An Azure connection string or storage account key was found and redacted.",
                GetLineNumber(content, azureMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(azureMatch.Value)));
        }

        if (GcpServiceAccountPattern().Match(content) is { Success: true } gcpMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET009",
                "Possible GCP service account key found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A Google Cloud service account JSON key was found.",
                GetLineNumber(content, gcpMatch.Index),
                isBlocking: true));
        }

        if (JwtTokenPattern().Match(content) is { Success: true } jwtMatch &&
            !IsDocumentationMarkdownPath(relativePath))
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET010",
                "Possible JWT token found",
                Severity.Medium,
                Confidence.Medium,
                relativePath,
                "A JWT-like token was found and redacted.",
                GetLineNumber(content, jwtMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(jwtMatch.Value)));
        }

        if (RegistryTokenPattern().Match(content) is { Success: true } registryMatch)
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET011",
                "Possible registry token found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "An npm or PyPI registry token was found and redacted.",
                GetLineNumber(content, registryMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(registryMatch.Value)));
        }

        if (GenericApiKeyPattern().Match(content) is { Success: true } apiKeyMatch &&
            !IsPlaceholderValue(apiKeyMatch.Value) &&
            IsGenericApiKeyStrength(apiKeyMatch.Value))
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET012",
                "Possible generic API key found",
                Severity.Medium,
                Confidence.Low,
                relativePath,
                "A value matching a generic API key pattern was found and redacted.",
                GetLineNumber(content, apiKeyMatch.Index),
                redactedValue: SecretEvidenceRedactor.Redact(apiKeyMatch.Value)));
        }

        return findings;
    }

    private static Finding CreateFinding(
        string ruleId,
        string title,
        Severity severity,
        Confidence confidence,
        string filePath,
        string evidence,
        int? lineNumber = null,
        bool isBlocking = false,
        string redactedValue = "[redacted]")
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

    private static bool IsLikelySourceCodeMarker(
        string relativePath,
        string content,
        int matchIndex)
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

    private static bool IsLikelySourceCodePrivateKeyPattern(
        string relativePath,
        Match match)
    {
        if (!IsSourceCodePath(relativePath))
        {
            return false;
        }

        var matchedText = match.Value;
        return matchedText.Contains(@"[\s\S]", StringComparison.Ordinal) ||
               matchedText.Contains(@"\s", StringComparison.Ordinal) ||
               matchedText.Contains(".+?", StringComparison.Ordinal) ||
               matchedText.Contains(".*?", StringComparison.Ordinal);
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
        if (lower.Contains("${{", StringComparison.Ordinal) ||
            lower.Contains("${", StringComparison.Ordinal) ||
            lower.Contains("%", StringComparison.Ordinal))
        {
            return true;
        }

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
        var trimmed = value.Trim('"', '\'', '`').Trim();
        if (trimmed.Count(char.IsLetterOrDigit) < 20)
        {
            return false;
        }

        var hasUpper = false;
        var hasLower = false;
        var hasDigit = false;
        foreach (var character in trimmed)
        {
            hasUpper |= char.IsUpper(character);
            hasLower |= char.IsLower(character);
            hasDigit |= char.IsDigit(character);
            if (hasUpper && hasLower && hasDigit)
            {
                return true;
            }
        }

        return false;
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

    [GeneratedRegex(@"(?i)(npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_.-]{32,})")]
    private static partial Regex RegistryTokenPattern();

    [GeneratedRegex(@"(?i)(api[_-]?key|api[_-]?secret|apikey)\s*[:=]\s*['""]?[A-Za-z0-9_\-]{16,}['""]?")]
    private static partial Regex GenericApiKeyPattern();
}

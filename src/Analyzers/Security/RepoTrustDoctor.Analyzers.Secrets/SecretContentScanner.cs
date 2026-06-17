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
            !SecretPrivateKeyClassifier.ShouldSuppress(
                relativePath,
                content,
                privateKeyMarkerMatch,
                privateKeyBlockMatch))
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

        if (TryFindConnectionString(content, out var connectionStringMatch))
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

        if (TryGetGcpServiceAccountKeyIndex(content, out var gcpMatchIndex))
        {
            findings.Add(CreateFinding(
                "TRUST-SECRET009",
                "Possible GCP service account key found",
                Severity.High,
                Confidence.Medium,
                relativePath,
                "A Google Cloud service account JSON key was found.",
                GetLineNumber(content, gcpMatchIndex),
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

        if (GenericApiKeyPattern().Match(content) is { Success: true } apiKeyMatch)
        {
            var apiKeyValue = apiKeyMatch.Groups["value"].Value;
            if (!IsPlaceholderValue(apiKeyValue) &&
                IsGenericApiKeyStrength(apiKeyValue))
            {
                findings.Add(CreateFinding(
                    "TRUST-SECRET012",
                    "Possible generic API key found",
                    Severity.Medium,
                    Confidence.Low,
                    relativePath,
                    "A value matching a generic API key pattern was found and redacted.",
                    GetLineNumber(content, apiKeyMatch.Index),
                    redactedValue: SecretEvidenceRedactor.Redact(apiKeyValue)));
            }
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
         content.Contains("data source", StringComparison.OrdinalIgnoreCase));

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

    private static bool TryGetGcpServiceAccountKeyIndex(string content, out int matchIndex)
    {
        var serviceAccountMatch = GcpServiceAccountPattern().Match(content);
        if (serviceAccountMatch.Success &&
            GcpPrivateKeyPropertyPattern().IsMatch(content) &&
            GcpClientEmailPattern().IsMatch(content))
        {
            matchIndex = serviceAccountMatch.Index;
            return true;
        }

        matchIndex = -1;
        return false;
    }

    private static bool TryFindConnectionString(string content, out ConnectionStringCandidate candidate)
    {
        var lineStart = 0;
        while (lineStart < content.Length)
        {
            var lineEnd = content.IndexOf('\n', lineStart);
            if (lineEnd < 0)
            {
                lineEnd = content.Length;
            }

            var line = content[lineStart..lineEnd].TrimEnd('\r');
            var keyMatch = ConnectionStringKeyPattern().Match(line);
            if (keyMatch.Success)
            {
                var raw = line[keyMatch.Index..];
                var fields = ParseConnectionStringFields(raw);
                if (IsSecretConnectionString(fields))
                {
                    candidate = new ConnectionStringCandidate(raw, lineStart + keyMatch.Index);
                    return true;
                }
            }

            lineStart = lineEnd + 1;
        }

        candidate = default;
        return false;
    }

    private static Dictionary<string, string> ParseConnectionStringFields(string raw)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var key = part[..separator].Trim();
            var value = part[(separator + 1)..].Trim().Trim('"', '\'');
            if (key.Length > 0)
            {
                fields[key] = value;
            }
        }

        return fields;
    }

    private static bool IsSecretConnectionString(IReadOnlyDictionary<string, string> fields)
    {
        var hasServer = fields.ContainsKey("Server") ||
                        fields.ContainsKey("Host") ||
                        fields.ContainsKey("Data Source");
        if (!hasServer)
        {
            return false;
        }

        var password = fields.TryGetValue("Password", out var fullPassword)
            ? fullPassword
            : fields.TryGetValue("Pwd", out var shortPassword)
                ? shortPassword
                : null;

        return !string.IsNullOrWhiteSpace(password) &&
               !IsPlaceholderValue(password);
    }

    private static bool IsPlaceholderValue(string value)
    {
        var lower = value.Trim().Trim('"', '\'', '`').ToLowerInvariant();
        if (lower.Contains("${{", StringComparison.Ordinal) ||
            lower.Contains("${", StringComparison.Ordinal) ||
            lower.StartsWith('$') ||
            (lower.StartsWith('%') && lower.EndsWith('%')))
        {
            return true;
        }

        var normalized = PlaceholderSeparatorPattern().Replace(lower, "-").Trim('-');
        return normalized is "your-api-key" or
               "your-api-key-here" or
               "example" or
               "example-token" or
               "test-token" or
               "dummy" or
               "dummy-secret" or
               "changeme" or
               "placeholder" or
               "replace" or
               "replace-me" or
               "sample" or
               "sample-key" or
               "your-secret" or
               "abc123" ||
               normalized.StartsWith("your-api-key-", StringComparison.Ordinal) ||
               normalized.StartsWith("changeme", StringComparison.Ordinal) ||
               normalized.StartsWith("dummy-", StringComparison.Ordinal) ||
               normalized.StartsWith("example-token-", StringComparison.Ordinal) ||
               normalized.StartsWith("placeholder-", StringComparison.Ordinal) ||
               normalized.StartsWith("replace-me-", StringComparison.Ordinal) ||
               normalized.StartsWith("sample-key-", StringComparison.Ordinal) ||
               normalized.Contains("xxxx", StringComparison.Ordinal);
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

    [GeneratedRegex(@"(?i)(?:^|;|\s)(Server|Host|Data Source|Password|Pwd)\s*=")]
    private static partial Regex ConnectionStringKeyPattern();

    [GeneratedRegex(@"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+")]
    private static partial Regex SlackWebhookPattern();

    [GeneratedRegex(@"https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_/]+")]
    private static partial Regex DiscordWebhookPattern();

    [GeneratedRegex(@"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+")]
    private static partial Regex AzureConnectionStringPattern();

    [GeneratedRegex(@"""type""\s*:\s*""service_account""")]
    private static partial Regex GcpServiceAccountPattern();

    [GeneratedRegex(@"""private_key""\s*:\s*""[^""]*-----BEGIN PRIVATE KEY-----")]
    private static partial Regex GcpPrivateKeyPropertyPattern();

    [GeneratedRegex(@"""client_email""\s*:\s*""[^""]+@[^""]+\.iam\.gserviceaccount\.com""")]
    private static partial Regex GcpClientEmailPattern();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")]
    private static partial Regex JwtTokenPattern();

    [GeneratedRegex(@"(?i)(npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_.-]{32,})")]
    private static partial Regex RegistryTokenPattern();

    [GeneratedRegex(@"(?i)(?<key>api[_-]?key|api[_-]?secret|apikey)\s*[:=]\s*['""]?(?<value>[A-Za-z0-9_\-]{16,})['""]?")]
    private static partial Regex GenericApiKeyPattern();

    [GeneratedRegex(@"[^a-z0-9]+")]
    private static partial Regex PlaceholderSeparatorPattern();

    private readonly record struct ConnectionStringCandidate(string Value, int Index);
}

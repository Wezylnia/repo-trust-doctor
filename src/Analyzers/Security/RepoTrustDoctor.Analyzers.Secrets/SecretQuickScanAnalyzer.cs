using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Secrets;

public sealed partial class SecretQuickScanAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] SensitiveFileNames = [".env", ".env.production", "id_rsa"];
    private static readonly string[] SensitiveExtensions = [".pem", ".key"];

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
                findings.Add(CreateFinding("TRUST-SECRET003", "Possible GitHub token found", Severity.High, Confidence.Medium, relativePath, "A GitHub token-like value was found and redacted.", GetLineNumber(content, gitHubTokenMatch.Index)));
            }

            if (AwsAccessKeyPattern().Match(content) is { Success: true } awsAccessKeyMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET004", "Possible AWS access key found", Severity.High, Confidence.Medium, relativePath, "An AWS access key-like value was found and redacted.", GetLineNumber(content, awsAccessKeyMatch.Index)));
            }

            if (ConnectionStringPattern().Match(content) is { Success: true } connectionStringMatch)
            {
                findings.Add(CreateFinding("TRUST-SECRET005", "Possible database connection string found", Severity.High, Confidence.Medium, relativePath, "A connection string-like value was found and redacted.", GetLineNumber(content, connectionStringMatch.Index)));
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, Confidence confidence, string filePath, string evidence, int? lineNumber = null, bool isBlocking = false)
    {
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.Security,
            severity,
            confidence,
            title,
            [new Evidence("secret-pattern", evidence, filePath, lineNumber, "[redacted]")],
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

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex(@"gh[pousr]_[A-Za-z0-9_]{20,}")]
    private static partial Regex GitHubTokenPattern();

    [GeneratedRegex(@"AKIA[0-9A-Z]{16}")]
    private static partial Regex AwsAccessKeyPattern();

    [GeneratedRegex(@"(?i)(Server|Host|Data Source)\s*=.+;(User Id|Username|Uid)\s*=.+;(Password|Pwd)\s*=")]
    private static partial Regex ConnectionStringPattern();
}

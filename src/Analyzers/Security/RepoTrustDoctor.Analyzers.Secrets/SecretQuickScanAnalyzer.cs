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

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in Directory.EnumerateFiles(context.RepositoryPath, "*", SearchOption.AllDirectories)
                     .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)))
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

            var info = new FileInfo(file);
            if (info.Length > 512 * 1024)
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            if (PrivateKeyPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-SECRET002", "Possible private key marker found", Severity.Critical, Confidence.High, relativePath, "A private key block marker was found.", isBlocking: true));
            }

            if (GitHubTokenPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-SECRET003", "Possible GitHub token found", Severity.High, Confidence.Medium, relativePath, "A GitHub token-like value was found and redacted."));
            }

            if (AwsAccessKeyPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-SECRET004", "Possible AWS access key found", Severity.High, Confidence.Medium, relativePath, "An AWS access key-like value was found and redacted."));
            }

            if (ConnectionStringPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-SECRET005", "Possible database connection string found", Severity.High, Confidence.Medium, relativePath, "A connection string-like value was found and redacted."));
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, Confidence confidence, string filePath, string evidence, bool isBlocking = false)
    {
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.Security,
            severity,
            confidence,
            title,
            [new Evidence("secret-pattern", evidence, filePath, Value: "[redacted]")],
            new Recommendation("Manually verify the finding, rotate any exposed secret, and remove it from repository history if confirmed."),
            isBlocking);
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

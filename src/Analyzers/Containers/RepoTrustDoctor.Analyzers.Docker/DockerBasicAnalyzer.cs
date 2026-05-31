using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Docker;

public sealed partial class DockerBasicAnalyzer : IRepositoryAnalyzer
{
    public string Id => "docker-basic";

    public string DisplayName => "Docker Basic Checks";

    public AnalysisCategory Category => AnalysisCategory.Containers;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DOCKER001", "Dockerfile exists but .dockerignore is missing", AnalysisCategory.Containers, Severity.Medium, Confidence.High, "No .dockerignore file was found.", "Review the Dockerfile for reproducibility and runtime hardening."),
        new("TRUST-DOCKER002", "Docker base image uses latest tag", AnalysisCategory.Containers, Severity.Medium, Confidence.High, "A FROM instruction uses the latest tag.", "Pin Docker base images by digest or a specific version tag."),
        new("TRUST-DOCKER003", "Dockerfile does not declare a non-root USER", AnalysisCategory.Containers, Severity.Medium, Confidence.High, "No USER instruction was found.", "Add a USER instruction to run as a non-root user."),
        new("TRUST-DOCKER004", "Dockerfile does not declare HEALTHCHECK", AnalysisCategory.Containers, Severity.Low, Confidence.High, "No HEALTHCHECK instruction was found.", "Add a HEALTHCHECK for container orchestration."),
        new("TRUST-DOCKER005", "Dockerfile may define secret-like ENV", AnalysisCategory.Containers, Severity.High, Confidence.Medium, "The Dockerfile defines a secret-like environment variable.", "Avoid defining secrets in ENV variables. Use Docker build secrets or pass secrets at runtime instead."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var dockerfiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Dockerfile*")
            .ToArray();

        if (dockerfiles.Length == 0)
        {
            return AnalyzerResult.Completed([]);
        }

        var findings = new List<Finding>();
        if (!File.Exists(Path.Combine(context.RepositoryPath, ".dockerignore")))
        {
            findings.Add(CreateFinding("TRUST-DOCKER001", "Dockerfile exists but .dockerignore is missing", Severity.Medium, ".dockerignore", "No .dockerignore file was found at repository root."));
        }

        foreach (var dockerfile in dockerfiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(dockerfile))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(dockerfile, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, dockerfile);

            if (LatestImagePattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-DOCKER002", "Docker base image uses latest tag", Severity.Medium, relativePath, "A FROM instruction uses the latest tag."));
            }

            if (!UserPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-DOCKER003", "Dockerfile does not declare a non-root USER", Severity.Medium, relativePath, "No USER instruction was found."));
            }

            if (!HealthcheckPattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-DOCKER004", "Dockerfile does not declare HEALTHCHECK", Severity.Low, relativePath, "No HEALTHCHECK instruction was found."));
            }

            foreach (Match match in SecretEnvPattern().Matches(content))
            {
                var key = match.Groups["key"].Value;
                var redactedLine = $"ENV {key}=[redacted]";
                var evidenceText = $"Dockerfile defines secret-like ENV variable '{key}' with value redacted.";
                findings.Add(new Finding(
                    "TRUST-DOCKER005",
                    "Dockerfile may define secret-like ENV",
                    AnalysisCategory.Containers,
                    Severity.High,
                    Confidence.Medium,
                    "Dockerfile may define secret-like ENV",
                    [new Evidence("dockerfile", evidenceText, relativePath, GetLineNumber(content, match.Index), redactedLine)],
                    new Recommendation("Avoid defining secrets in ENV variables. Use Docker build secrets or pass secrets at runtime instead.")));
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence)
    {
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.Containers,
            severity,
            Confidence.High,
            title,
            [new Evidence("dockerfile", evidence, filePath)],
            new Recommendation("Review the Dockerfile for reproducibility and runtime hardening."));
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

    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+:latest\b")]
    private static partial Regex LatestImagePattern();

    [GeneratedRegex(@"(?mi)^\s*USER\s+\S+")]
    private static partial Regex UserPattern();

    [GeneratedRegex(@"(?mi)^\s*HEALTHCHECK\b")]
    private static partial Regex HealthcheckPattern();

    [GeneratedRegex(@"(?mi)^\s*ENV\s+(?<key>PASSWORD|TOKEN|SECRET|API_KEY)\b\s*(?:=\s*|\s+)(?<value>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SecretEnvPattern();
}

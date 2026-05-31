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

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var dockerfiles = Directory.EnumerateFiles(context.RepositoryPath, "Dockerfile*", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
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

    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+:latest\b")]
    private static partial Regex LatestImagePattern();

    [GeneratedRegex(@"(?mi)^\s*USER\s+\S+")]
    private static partial Regex UserPattern();

    [GeneratedRegex(@"(?mi)^\s*HEALTHCHECK\b")]
    private static partial Regex HealthcheckPattern();
}

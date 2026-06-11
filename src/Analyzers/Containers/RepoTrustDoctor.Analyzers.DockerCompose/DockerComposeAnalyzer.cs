using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DockerCompose;

public sealed partial class DockerComposeAnalyzer : IRepositoryAnalyzer
{
    public string Id => "docker-compose";

    public string DisplayName => "Docker Compose Security";

    public AnalysisCategory Category => AnalysisCategory.Containers;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-COMP001", "Docker Compose service runs in privileged mode", AnalysisCategory.Containers, Severity.High, Confidence.High,
            "A service is configured with privileged: true.", "Avoid privileged mode unless absolutely necessary. It grants full host capabilities."),
        new("TRUST-COMP002", "Docker Compose service uses host network mode", AnalysisCategory.Containers, Severity.Medium, Confidence.High,
            "A service uses network_mode: host.", "Host network mode bypasses container network isolation. Use bridge networks instead."),
        new("TRUST-COMP003", "Docker Compose mounts host directory", AnalysisCategory.Containers, Severity.Medium, Confidence.Medium,
            "A service mounts a host directory with read-write access.", "Review host volume mounts. Prefer named volumes and ensure paths are intentional."),
        new("TRUST-COMP004", "Docker Compose exposes broad port range", AnalysisCategory.Containers, Severity.Low, Confidence.High,
            "A port mapping binds to all interfaces (0.0.0.0).", "Bind services to specific interfaces when possible, or use reverse proxy."),
        new("TRUST-COMP005", "Docker Compose may define secrets in environment", AnalysisCategory.Containers, Severity.High, Confidence.Medium,
            "A service defines secret-like environment variables.", "Use Docker secrets or external secret management. Avoid plaintext secrets in Compose files."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var pattern in new[] { "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml" })
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!RepositoryFileSystem.CanReadAsText(file))
                {
                    continue;
                }

                var content = await File.ReadAllTextAsync(file, cancellationToken);
                var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

                CheckPrivileged(content, relativePath, findings);
                CheckHostNetwork(content, relativePath, findings);
                CheckHostVolumeMounts(content, relativePath, findings);
                CheckBroadPorts(content, relativePath, findings);
                CheckSecretEnvironment(content, relativePath, findings);
            }
        }

        return AnalyzerResult.Completed(findings);
    }

    private static void CheckPrivileged(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in PrivilegedPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-COMP001", "Docker Compose service runs in privileged mode",
                Severity.High, relativePath, "A service is configured with privileged: true.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckHostNetwork(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in HostNetworkPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-COMP002", "Docker Compose service uses host network mode",
                Severity.Medium, relativePath, "A service uses network_mode: host.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckHostVolumeMounts(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in HostVolumePattern().Matches(content))
        {
            var path = match.Groups["path"].Value;
            findings.Add(CreateFinding("TRUST-COMP003", "Docker Compose mounts host directory",
                Severity.Medium, relativePath, $"Mounts host path '{path}'.",
                GetLineNumber(content, match.Index), Confidence.Medium));
        }
    }

    private static void CheckBroadPorts(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in BroadPortPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-COMP004", "Docker Compose exposes broad port range",
                Severity.Low, relativePath, "Port mapping binds to 0.0.0.0 (all interfaces).",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckSecretEnvironment(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in SecretEnvPattern().Matches(content))
        {
            var key = match.Groups["key"].Value;
            findings.Add(CreateFinding("TRUST-COMP005", "Docker Compose may define secrets in environment",
                Severity.High, relativePath, $"Secret-like environment variable '{key}' defined.",
                GetLineNumber(content, match.Index), Confidence.Medium));
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.Containers, severity, confidence, title,
            [new Evidence("compose", evidence, filePath, lineNumber)],
            new Recommendation("Review the Docker Compose configuration and apply the recommended fix."));
    }

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    [GeneratedRegex(@"(?m)^\s*privileged\s*:\s*true\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex PrivilegedPattern();

    [GeneratedRegex(@"(?m)^\s*network_mode\s*:\s*['""]?host['""]?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex HostNetworkPattern();

    [GeneratedRegex(@"(?m)^\s*-\s*(?<path>/[^:\n]+):/[^:\n]*(?::rw)?\s*$")]
    private static partial Regex HostVolumePattern();

    [GeneratedRegex(@"(?m)^\s*-\s*['""]?0\.0\.0\.0:\d+.*['""]?\s*$")]
    private static partial Regex BroadPortPattern();

    [GeneratedRegex(@"(?mi)^\s*(?:-\s+)?(?<key>PASSWORD|TOKEN|SECRET|API_KEY)\s*[=:]\s*\S+")]
    private static partial Regex SecretEnvPattern();
}

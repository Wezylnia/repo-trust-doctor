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
        new("TRUST-COMP006", "Docker Compose mounts Docker socket", AnalysisCategory.Containers, Severity.Critical, Confidence.High,
            "A service mounts the Docker socket.", "Do not mount the Docker socket into application services. Use a dedicated isolated builder."),
        new("TRUST-COMP007", "Docker Compose loads environment from .env-like file", AnalysisCategory.Containers, Severity.Medium, Confidence.Medium,
            "A service loads environment from a .env-like file.", "Review env_file entries. Avoid loading .env.production or .env.local into containers."),
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
                CheckDockerSocketMount(content, relativePath, findings);
                CheckEnvFileLoading(content, relativePath, findings);
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
            if (IsDockerSocketPath(path))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-COMP003", "Docker Compose mounts host directory",
                Severity.Medium, relativePath, $"Mounts host path '{path}'.",
                GetLineNumber(content, match.Index), Confidence.Medium));
        }

        foreach (var mount in EnumerateLongBindMounts(content))
        {
            if (IsDockerSocketPath(mount.Source) || IsDockerSocketPath(mount.Target))
            {
                continue;
            }

            findings.Add(CreateFinding(
                "TRUST-COMP003",
                "Docker Compose mounts host directory",
                mount.ReadOnly ? Severity.Low : Severity.Medium,
                relativePath,
                $"Mounts host path '{mount.Source}' using long bind syntax.",
                mount.LineNumber,
                mount.ReadOnly ? Confidence.Low : Confidence.Medium));
        }
    }

    private static void CheckBroadPorts(string content, string relativePath, List<Finding> findings)
    {
        if (IsLowSignalComposePath(relativePath))
        {
            return;
        }

        foreach (Match match in BroadPortPattern().Matches(content))
        {
            findings.Add(CreateFinding("TRUST-COMP004", "Docker Compose exposes broad port range",
                Severity.Low, relativePath, "Port mapping binds to all interfaces by default or through 0.0.0.0.",
                GetLineNumber(content, match.Index)));
        }
    }

    private static void CheckSecretEnvironment(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in SecretEnvPattern().Matches(content))
        {
            var key = match.Groups["key"].Value;
            var value = match.Groups["value"].Value.Trim();
            if (IsSafeEnvironmentValue(value))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-COMP005", "Docker Compose may define secrets in environment",
                Severity.High, relativePath, $"Secret-like environment variable '{key}' defined.",
                GetLineNumber(content, match.Index), Confidence.Medium));
        }
    }

    private static void CheckDockerSocketMount(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in DockerSocketPattern().Matches(content))
        {
            var socketPath = match.Groups["socket"].Value;
            findings.Add(CreateFinding("TRUST-COMP006", "Docker Compose mounts Docker socket",
                Severity.Critical, relativePath, $"Mounts Docker socket '{socketPath}'. This grants high privilege over the host Docker daemon.",
                GetLineNumber(content, match.Index), isBlocking: true));
        }

        foreach (var mount in EnumerateLongBindMounts(content))
        {
            if (!IsDockerSocketPath(mount.Source) && !IsDockerSocketPath(mount.Target))
            {
                continue;
            }

            findings.Add(CreateFinding("TRUST-COMP006", "Docker Compose mounts Docker socket",
                Severity.Critical, relativePath, $"Mounts Docker socket '{mount.Source}' using long bind syntax.",
                mount.LineNumber, isBlocking: true));
        }
    }

    private static IEnumerable<LongBindMount> EnumerateLongBindMounts(string content)
    {
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            if (!LongVolumeTypeBindPattern().IsMatch(lines[index]))
            {
                continue;
            }

            var baseIndent = CountIndent(lines[index]);
            string? source = null;
            string? target = null;
            var readOnly = false;

            for (var cursor = index + 1; cursor < lines.Length; cursor++)
            {
                var line = lines[cursor];
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                if (CountIndent(line) <= baseIndent)
                {
                    break;
                }

                source ??= ReadYamlScalar(line, "source");
                source ??= ReadYamlScalar(line, "src");
                target ??= ReadYamlScalar(line, "target");
                target ??= ReadYamlScalar(line, "dst");
                target ??= ReadYamlScalar(line, "destination");

                var readOnlyValue = ReadYamlScalar(line, "read_only") ?? ReadYamlScalar(line, "readonly");
                if (string.Equals(readOnlyValue, "true", StringComparison.OrdinalIgnoreCase))
                {
                    readOnly = true;
                }
            }

            if (!string.IsNullOrWhiteSpace(source))
            {
                yield return new LongBindMount(source, target ?? string.Empty, readOnly, index + 1);
            }
        }
    }

    private static string? ReadYamlScalar(string line, string key)
    {
        var match = Regex.Match(line, $"^\\s*{Regex.Escape(key)}\\s*:\\s*(?<value>.+?)\\s*$", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["value"].Value.Trim().Trim('"', '\'') : null;
    }

    private static bool IsSafeEnvironmentValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var trimmed = value.Trim('"', '\'');
        return trimmed.StartsWith("${", StringComparison.Ordinal) ||
               trimmed.StartsWith("$", StringComparison.Ordinal) ||
               trimmed.Equals("example", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("placeholder", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("changeme", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("replace-me", StringComparison.OrdinalIgnoreCase);
    }

    private static void CheckEnvFileLoading(string content, string relativePath, List<Finding> findings)
    {
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var match = EnvFileLinePattern().Match(lines[index]);
            if (!match.Success)
            {
                continue;
            }

            var inlineEntry = NormalizeEnvFileEntry(match.Groups["file"].Value);
            if (!string.IsNullOrWhiteSpace(inlineEntry))
            {
                AddEnvFileFindingIfRisky(inlineEntry, relativePath, findings, index + 1);
                continue;
            }

            var parentIndent = match.Groups["indent"].Value.Length;
            for (var itemIndex = index + 1; itemIndex < lines.Length; itemIndex++)
            {
                var line = lines[itemIndex];
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
                {
                    continue;
                }

                if (CountIndent(line) <= parentIndent)
                {
                    break;
                }

                var itemMatch = EnvFileItemPattern().Match(line);
                if (!itemMatch.Success)
                {
                    continue;
                }

                var listEntry = NormalizeEnvFileEntry(itemMatch.Groups["file"].Value);
                AddEnvFileFindingIfRisky(listEntry, relativePath, findings, itemIndex + 1);
            }
        }
    }

    private static void AddEnvFileFindingIfRisky(string envFile, string relativePath, List<Finding> findings, int lineNumber)
    {
        if (string.IsNullOrWhiteSpace(envFile) ||
            envFile.EndsWith(".example", StringComparison.OrdinalIgnoreCase) ||
            envFile.Contains("example.env", StringComparison.OrdinalIgnoreCase) ||
            envFile.Contains("sample", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var fileName = Path.GetFileName(envFile);
        if (fileName.StartsWith(".env", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".secret", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".secrets", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(CreateFinding("TRUST-COMP007", "Docker Compose loads .env-like file",
                Severity.Medium, relativePath, $"Loads environment from '{envFile}'. Review for secrets or sensitive configuration.",
                lineNumber, Confidence.Medium));
        }
    }

    private static string NormalizeEnvFileEntry(string value)
    {
        var trimmed = value.Trim();
        var commentIndex = trimmed.IndexOf(" #", StringComparison.Ordinal);
        if (commentIndex >= 0)
        {
            trimmed = trimmed[..commentIndex].Trim();
        }

        if (trimmed.StartsWith("path:", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["path:".Length..].Trim();
        }

        return trimmed.Trim('"', '\'');
    }

    private static bool IsLowSignalComposePath(string relativePath) =>
        RepositoryPathClassifier.Classify(relativePath).HasAny(
            RepositoryPathClassification.Tooling |
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example |
            RepositoryPathClassification.Documentation |
            RepositoryPathClassification.Generated |
            RepositoryPathClassification.Template);

    private static int CountIndent(string line)
    {
        var count = 0;
        while (count < line.Length && char.IsWhiteSpace(line[count]))
        {
            count++;
        }

        return count;
    }

    private static bool IsDockerSocketPath(string path) =>
        path.Equals("/var/run/docker.sock", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/run/docker.sock", StringComparison.OrdinalIgnoreCase);

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High, bool isBlocking = false)
    {
        return new Finding(ruleId, title, AnalysisCategory.Containers, severity, confidence, title,
            [new Evidence("compose", evidence, filePath, lineNumber)],
            new Recommendation("Review the Docker Compose configuration and apply the recommended fix."),
            IsBlocking: isBlocking);
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

    [GeneratedRegex(@"(?m)^\s*-\s*['""]?(?<path>/[^:'""\n]+):/[^:'""\n]*(?::[A-Za-z]+)?['""]?\s*$")]
    private static partial Regex HostVolumePattern();

    [GeneratedRegex(@"(?m)^\s*-\s*['""]?(?:(?:0\.0\.0\.0|\*)\s*:\s*)?\d+(?:-\d+)?\s*:\s*\d+(?:-\d+)?(?:/\w+)?['""]?\s*$")]
    private static partial Regex BroadPortPattern();

    [GeneratedRegex(@"(?mi)^\s*(?:-\s+)?(?<key>PASSWORD|TOKEN|SECRET|API_KEY)\s*[=:]\s*(?<value>\S*)")]
    private static partial Regex SecretEnvPattern();

    [GeneratedRegex(@"(?m)-\s*['""]?(?<socket>/var/run/docker\.sock|/run/docker\.sock)\s*:")]
    private static partial Regex DockerSocketPattern();

    [GeneratedRegex(@"^(?<indent>\s*)env_file\s*:\s*(?<file>.*)$")]
    private static partial Regex EnvFileLinePattern();

    [GeneratedRegex(@"^\s*-\s*(?<file>[^#]+)")]
    private static partial Regex EnvFileItemPattern();

    [GeneratedRegex(@"(?mi)^\s*-\s*type\s*:\s*bind\s*$")]
    private static partial Regex LongVolumeTypeBindPattern();

    private sealed record LongBindMount(string Source, string Target, bool ReadOnly, int LineNumber);
}

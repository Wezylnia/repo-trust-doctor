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
        new("TRUST-DOCKER006", "Dockerfile does not appear to use multi-stage build", AnalysisCategory.Containers, Severity.Low, Confidence.Medium, "Dockerfile has only one FROM instruction.", "Use multi-stage builds to reduce image size and improve security by separating build dependencies from the runtime image."),
        new("TRUST-DOCKER007", "Dockerfile copies entire context before dependency restore", AnalysisCategory.Containers, Severity.Low, Confidence.Medium, "COPY . . appears before a dependency restore or install step.", "Copy dependency manifest files first, restore dependencies, then copy the rest of the source."),
        new("TRUST-DOCKER008", "Dockerfile separates apt-get update from install", AnalysisCategory.Containers, Severity.Low, Confidence.Medium, "apt-get update and apt-get install appear in separate RUN instructions.", "Combine apt-get update and apt-get install in one RUN instruction and clean package lists in the same layer."),
        new("TRUST-DOCKER009", "Dockerfile uses ADD instead of COPY", AnalysisCategory.Containers, Severity.Low, Confidence.High, "ADD is used where COPY would be sufficient.", "Prefer COPY over ADD unless you specifically need tar extraction or URL fetching."),
        new("TRUST-DOCKER010", "Dockerfile uses sudo", AnalysisCategory.Containers, Severity.High, Confidence.High, "sudo is used in a RUN instruction.", "Remove sudo usage. Docker containers normally run as root, and sudo adds complexity without real isolation."),
        new("TRUST-DOCKER011", "Dockerfile EXPOSE uses overly broad port range", AnalysisCategory.Containers, Severity.Low, Confidence.Medium, "EXPOSE specifies a port range.", "Expose only the specific ports your application needs."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var dockerfiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Dockerfile*")
            .Select(file => CreateDockerfileCandidate(context.RepositoryPath, file))
            .Where(candidate => candidate is not null)
            .Select(candidate => candidate!)
            .ToArray();

        if (dockerfiles.Length == 0)
        {
            return AnalyzerResult.Completed([]);
        }

        var findings = new List<Finding>();
        if (dockerfiles.Any(candidate => !candidate.IsBuildSupport) &&
            !File.Exists(Path.Combine(context.RepositoryPath, ".dockerignore")))
        {
            findings.Add(CreateFinding("TRUST-DOCKER001", "Dockerfile exists but .dockerignore is missing", Severity.Medium, ".dockerignore", "No .dockerignore file was found at repository root."));
        }

        foreach (var dockerfile in dockerfiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(dockerfile.FullPath))
            {
                continue;
            }

            var content = await File.ReadAllTextAsync(dockerfile.FullPath, cancellationToken);
            var relativePath = dockerfile.RelativePath;
            var isBuildSupport = dockerfile.IsBuildSupport ||
                                 IsNestedBuildOnlyDockerfile(relativePath, content);

            if (LatestImagePattern().IsMatch(content))
            {
                findings.Add(CreateFinding("TRUST-DOCKER002", "Docker base image uses latest tag", Severity.Medium, relativePath, "A FROM instruction uses the latest tag."));
            }

            if (!isBuildSupport)
            {
                CheckRuntimeHardening(content, relativePath, findings);
                CheckCopyBeforeRestore(content, relativePath, findings);
            }

            CheckAptGetLayering(content, relativePath, findings);
            CheckAddVsCopy(content, relativePath, findings);
            CheckSudoUsage(content, relativePath, findings);
            CheckExposePortRange(content, relativePath, findings);

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

    private static void CheckRuntimeHardening(string content, string relativePath, List<Finding> findings)
    {
        if (!UserPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-DOCKER003", "Dockerfile does not declare a non-root USER", Severity.Medium, relativePath, "No USER instruction was found."));
        }

        if (ExposeInstructionPattern().IsMatch(content) &&
            !HealthcheckPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-DOCKER004", "Dockerfile does not declare HEALTHCHECK", Severity.Low, relativePath, "No HEALTHCHECK instruction was found."));
        }

        var fromCount = FromInstructionPattern().Matches(content).Count;
        if (fromCount == 1 && BuildInstructionPattern().IsMatch(content))
        {
            findings.Add(CreateFinding(
                "TRUST-DOCKER006",
                "Dockerfile does not appear to use multi-stage build",
                Severity.Low,
                relativePath,
                "Dockerfile has only one FROM instruction.",
                Confidence.Medium,
                "Use multi-stage builds to reduce image size and improve security by separating build dependencies from the runtime image."));
        }
    }

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, Confidence confidence = Confidence.High, string recommendationText = "Review the Dockerfile for reproducibility and runtime hardening.")
    {
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.Containers,
            severity,
            confidence,
            title,
            [new Evidence("dockerfile", evidence, filePath)],
            new Recommendation(recommendationText));
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

    private static DockerfileCandidate? CreateDockerfileCandidate(string repositoryPath, string filePath)
    {
        var relativePath = Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/');
        if (IsIgnoredDockerfile(relativePath))
        {
            return null;
        }

        return new DockerfileCandidate(filePath, relativePath, IsBuildSupportDockerfile(relativePath));
    }

    private static bool IsIgnoredDockerfile(string relativePath)
    {
        var fileName = Path.GetFileName(relativePath);

        return RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath) ||
               fileName.EndsWith(".tt", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".tmpl", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".template", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".test", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith("tests/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith("test/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/test/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/fixtures/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith("fixtures/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/templates/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith("templates/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith(".devcontainer/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/.devcontainer/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.StartsWith("devcontainer/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("/devcontainer/", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("integration-test", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("smoke-test", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("dockertest", StringComparison.OrdinalIgnoreCase) ||
               relativePath.Contains("testfixtures", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBuildSupportDockerfile(string relativePath) =>
        RepositoryPathClassifier.Classify(relativePath)
            .HasAny(RepositoryPathClassification.Tooling) ||
        HasPathSegment(relativePath, "ci") ||
        HasPathSegment(relativePath, ".github") ||
        HasPathSegment(relativePath, ".circleci") ||
        HasPathSegment(relativePath, ".azure-pipelines");

    private static bool IsNestedBuildOnlyDockerfile(string relativePath, string content) =>
        relativePath.Contains('/', StringComparison.Ordinal) &&
        (!RuntimeInstructionPattern().IsMatch(content) ||
         TestRuntimeInstructionPattern().IsMatch(content));

    private static bool HasPathSegment(string relativePath, string segment) =>
        relativePath.Split('/').Contains(segment, StringComparer.OrdinalIgnoreCase);

    private static void CheckCopyBeforeRestore(string content, string relativePath, List<Finding> findings)
    {
        var copyAllMatch = CopyAllPattern().Match(content);
        if (!copyAllMatch.Success)
        {
            return;
        }

        var restoreMatch = RestoreOrInstallPattern().Match(content);
        if (!restoreMatch.Success || copyAllMatch.Index > restoreMatch.Index)
        {
            return;
        }

        findings.Add(CreateFinding(
            "TRUST-DOCKER007",
            "Dockerfile copies entire context before dependency restore",
            Severity.Low,
            relativePath,
            "COPY . . appears before a dependency restore or install step.",
            Confidence.Medium,
            "Copy dependency manifest files first, restore dependencies, then copy the rest of the source."));
    }

    private static void CheckAptGetLayering(string content, string relativePath, List<Finding> findings)
    {
        var runMatches = RunInstructionPattern().Matches(content);
        var updateRunIndex = -1;
        for (var index = 0; index < runMatches.Count; index++)
        {
            var runLine = runMatches[index].Value;
            if (AptGetUpdatePattern().IsMatch(runLine) && !AptGetInstallPattern().IsMatch(runLine))
            {
                updateRunIndex = index;
                continue;
            }

            if (updateRunIndex >= 0 && AptGetInstallPattern().IsMatch(runLine))
            {
                findings.Add(CreateFinding(
                    "TRUST-DOCKER008",
                    "Dockerfile separates apt-get update from install",
                    Severity.Low,
                    relativePath,
                    "apt-get update and apt-get install appear in separate RUN instructions.",
                    Confidence.Medium,
                    "Combine apt-get update and apt-get install in one RUN instruction and clean package lists in the same layer."));
                return;
            }
        }
    }

    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+:latest\b")]
    private static partial Regex LatestImagePattern();

    [GeneratedRegex(@"(?mi)^\s*USER\s+\S+")]
    private static partial Regex UserPattern();

    [GeneratedRegex(@"(?mi)^\s*EXPOSE\s+\S+")]
    private static partial Regex ExposeInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*(?:CMD|ENTRYPOINT|EXPOSE|HEALTHCHECK)\b")]
    private static partial Regex RuntimeInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*(?:CMD|ENTRYPOINT)\b.*\b(?:run[_-]?tests?|pytest|phpunit|rspec|go\s+test|dotnet\s+test)\b")]
    private static partial Regex TestRuntimeInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.*\b(?:dotnet\s+publish|npm\s+run\s+build|pnpm\s+build|yarn\s+build|go\s+build|cargo\s+build|cmake|make|mvn\s+package|gradle\s+build)\b")]
    private static partial Regex BuildInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*HEALTHCHECK\b")]
    private static partial Regex HealthcheckPattern();

    [GeneratedRegex(@"(?mi)^\s*FROM\s+\S+")]
    private static partial Regex FromInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*ENV\s+(?<key>PASSWORD|TOKEN|SECRET|API_KEY)\b\s*(?:=\s*|\s+)(?<value>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SecretEnvPattern();

    [GeneratedRegex(@"(?mi)^\s*COPY\s+(?:--[^\s]+\s+)*\.\s+\.\s*$")]
    private static partial Regex CopyAllPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.*\b(dotnet\s+restore|npm\s+(?:ci|install)|pnpm\s+install|yarn\s+install|pip\s+install|poetry\s+install|uv\s+sync|go\s+mod\s+download|mvn\s+(?:dependency:go-offline|install)|gradle\s+dependencies)\b")]
    private static partial Regex RestoreOrInstallPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.+$")]
    private static partial Regex RunInstructionPattern();

    [GeneratedRegex(@"\bapt-get\s+update\b", RegexOptions.IgnoreCase)]
    private static partial Regex AptGetUpdatePattern();

    [GeneratedRegex(@"\bapt-get\s+install\b", RegexOptions.IgnoreCase)]
    private static partial Regex AptGetInstallPattern();

    private static void CheckAddVsCopy(string content, string relativePath, List<Finding> findings)
    {
        var addMatches = AddInstructionPattern().Matches(content);
        foreach (Match match in addMatches)
        {
            var addValue = match.Groups["src"].Value;
            // ADD with a URL is legitimate for fetching remote archives,
            // but ADD when copying local files should be flagged.
            if (addValue.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                addValue.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(new Finding(
                "TRUST-DOCKER009",
                "Dockerfile uses ADD instead of COPY",
                AnalysisCategory.Containers,
                Severity.Low,
                Confidence.High,
                "ADD is used where COPY would be sufficient.",
                [new Evidence("dockerfile", "ADD is used to copy local files; prefer COPY for clarity and safety.", relativePath, GetLineNumber(content, match.Index), match.Value.Trim())],
                new Recommendation("Prefer COPY over ADD unless you specifically need tar extraction or URL fetching.")));
            // Only report once per file
            break;
        }
    }

    private static void CheckSudoUsage(string content, string relativePath, List<Finding> findings)
    {
        var sudoMatches = SudoPattern().Matches(content);
        foreach (Match match in sudoMatches)
        {
            findings.Add(new Finding(
                "TRUST-DOCKER010",
                "Dockerfile uses sudo",
                AnalysisCategory.Containers,
                Severity.High,
                Confidence.High,
                "sudo is used in a RUN instruction.",
                [new Evidence("dockerfile", "sudo usage detected in Dockerfile. Containers should not rely on sudo.", relativePath, GetLineNumber(content, match.Index), match.Value.Trim())],
                new Recommendation("Remove sudo usage. Docker containers normally run as root, and sudo adds complexity without real isolation.")));
            break;
        }
    }

    private static void CheckExposePortRange(string content, string relativePath, List<Finding> findings)
    {
        var exposeMatches = ExposePortRangePattern().Matches(content);
        foreach (Match match in exposeMatches)
        {
            var startPort = int.Parse(match.Groups["start"].Value);
            var endPort = int.Parse(match.Groups["end"].Value);
            var range = endPort - startPort;
            if (range > 100)
            {
                findings.Add(new Finding(
                    "TRUST-DOCKER011",
                    "Dockerfile EXPOSE uses overly broad port range",
                    AnalysisCategory.Containers,
                    Severity.Low,
                    Confidence.Medium,
                    $"EXPOSE uses a broad port range ({startPort}-{endPort}, span of {range}).",
                    [new Evidence("dockerfile", $"EXPOSE {startPort}-{endPort} exposes {range + 1} ports.", relativePath, GetLineNumber(content, match.Index), match.Value.Trim())],
                    new Recommendation("Expose only the specific ports your application needs.")));
                break;
            }
        }
    }

    [GeneratedRegex(@"(?mi)^\s*ADD\s+(?<src>\S+)\s+\S+")]
    private static partial Regex AddInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.*\bsudo\b")]
    private static partial Regex SudoPattern();

    [GeneratedRegex(@"(?mi)^\s*EXPOSE\s+(?<start>\d+)-(?<end>\d+)")]
    private static partial Regex ExposePortRangePattern();

    private sealed record DockerfileCandidate(string FullPath, string RelativePath, bool IsBuildSupport);
}

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
        new("TRUST-DOCKER012", "Dockerfile pipes remote installer to shell", AnalysisCategory.Containers, Severity.High, Confidence.High, "A RUN instruction downloads remote content and pipes it into a shell.", "Download release artifacts with pinned checksums or signatures instead of piping network content directly to a shell."),
        new("TRUST-DOCKER014", "Dockerfile disables healthcheck", AnalysisCategory.Containers, Severity.Low, Confidence.High, "HEALTHCHECK NONE disables container health reporting.", "Remove HEALTHCHECK NONE and add an appropriate health probe for long-running service images."),
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
            var logicalContent = NormalizeLogicalInstructions(content);
            var relativePath = dockerfile.RelativePath;
            var isBuildSupport = dockerfile.IsBuildSupport ||
                                 IsNestedBuildOnlyDockerfile(relativePath, logicalContent);
            var stages = ExtractStages(logicalContent);

            var finalStage = stages.LastOrDefault();
            if (finalStage is not null && IsMutableBaseImage(finalStage.BaseImage))
            {
                findings.Add(CreateFinding("TRUST-DOCKER002", "Docker base image uses latest tag", Severity.Medium, relativePath, $"Final FROM image `{finalStage.BaseImage}` uses latest or no tag."));
            }

            if (!isBuildSupport)
            {
                CheckRuntimeHardening(finalStage?.Content ?? logicalContent, logicalContent, relativePath, findings);
                foreach (var stage in stages.Length == 0 ? [new DockerfileStage(string.Empty, logicalContent)] : stages)
                {
                    CheckCopyBeforeRestore(stage.Content, relativePath, findings);
                }
            }

            foreach (var stage in stages.Length == 0 ? [new DockerfileStage(string.Empty, logicalContent)] : stages)
            {
                CheckAptGetLayering(stage.Content, relativePath, findings);
                CheckRemoteInstallerPipe(stage.Content, relativePath, findings);
            }

            CheckAddVsCopy(logicalContent, relativePath, findings);
            CheckSudoUsage(logicalContent, relativePath, findings);
            CheckExposePortRange(logicalContent, relativePath, findings);

            foreach (Match match in SecretEnvPattern().Matches(logicalContent))
            {
                var key = match.Groups["key"].Value;
                var value = match.Groups["value"].Value;
                if (IsSafeEnvironmentReference(value))
                {
                    continue;
                }

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

    private static void CheckRuntimeHardening(string runtimeContent, string fullContent, string relativePath, List<Finding> findings)
    {
        var effectiveUser = GetEffectiveUser(runtimeContent);
        if (effectiveUser is null)
        {
            findings.Add(CreateFinding("TRUST-DOCKER003", "Dockerfile does not declare a non-root USER", Severity.Medium, relativePath, "No USER instruction was found."));
        }
        else if (IsRootUser(effectiveUser))
        {
            findings.Add(CreateFinding("TRUST-DOCKER003", "Dockerfile does not declare a non-root USER", Severity.Medium, relativePath, $"Final effective USER is `{effectiveUser}`."));
        }
        else if (IsVariableUser(effectiveUser))
        {
            findings.Add(CreateFinding(
                "TRUST-DOCKER003",
                "Dockerfile does not declare a non-root USER",
                Severity.Medium,
                relativePath,
                $"Final effective USER `{effectiveUser}` is variable-based and cannot be verified statically.",
                Confidence.Medium));
        }

        if (ExposeInstructionPattern().IsMatch(runtimeContent) &&
            !HealthcheckPattern().IsMatch(runtimeContent))
        {
            findings.Add(CreateFinding("TRUST-DOCKER004", "Dockerfile does not declare HEALTHCHECK", Severity.Low, relativePath, "No HEALTHCHECK instruction was found."));
        }

        if (ExposeInstructionPattern().IsMatch(runtimeContent) &&
            HealthcheckNonePattern().IsMatch(runtimeContent))
        {
            findings.Add(CreateFinding(
                "TRUST-DOCKER014",
                "Dockerfile disables healthcheck",
                Severity.Low,
                relativePath,
                "HEALTHCHECK NONE disables container health reporting.",
                recommendationText: "Remove HEALTHCHECK NONE and add an appropriate health probe for long-running service images."));
        }

        var fromCount = FromInstructionPattern().Matches(fullContent).Count;
        if (fromCount == 1 && BuildInstructionPattern().IsMatch(fullContent))
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

    private static string? GetEffectiveUser(string runtimeContent)
    {
        var matches = UserPattern().Matches(runtimeContent);
        if (matches.Count == 0)
        {
            return null;
        }

        return matches[^1].Groups["user"].Value.Trim();
    }

    private static bool IsRootUser(string user)
    {
        var normalized = user.Trim().Trim('"', '\'');
        var primary = normalized.Split(':', 2)[0];
        return primary.Equals("root", StringComparison.OrdinalIgnoreCase) ||
               primary.Equals("0", StringComparison.Ordinal);
    }

    private static bool IsVariableUser(string user) =>
        user.Contains('$', StringComparison.Ordinal) ||
        user.Contains('{', StringComparison.Ordinal) ||
        user.Contains('}', StringComparison.Ordinal);

    private static bool IsSafeEnvironmentReference(string value)
    {
        var normalized = value.Trim().Trim('"', '\'').Trim();
        if (normalized.Length == 0)
        {
            return true;
        }

        if (VariableReferencePattern().IsMatch(normalized))
        {
            return true;
        }

        return normalized.Equals("placeholder", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("example", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("changeme", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("change-me", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("replace-me", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("redacted", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("<redacted>", StringComparison.OrdinalIgnoreCase);
    }

    private static DockerfileStage[] ExtractStages(string content)
    {
        var matches = FromInstructionPattern().Matches(content);
        if (matches.Count == 0)
        {
            return [];
        }

        return matches
            .Cast<Match>()
            .Select((match, index) =>
            {
                var stageEnd = index + 1 < matches.Count
                    ? matches[index + 1].Index
                    : content.Length;
                return new DockerfileStage(
                    match.Groups["image"].Value.Trim(),
                    content[match.Index..stageEnd]);
            })
            .ToArray();
    }

    private static string NormalizeLogicalInstructions(string content)
    {
        return DockerLineContinuationPattern().Replace(content, " ");
    }

    private static bool IsMutableBaseImage(string image)
    {
        if (string.IsNullOrWhiteSpace(image) ||
            image.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var lastSlash = image.LastIndexOf('/');
        var lastColon = image.LastIndexOf(':');
        if (lastColon <= lastSlash)
        {
            return true;
        }

        return image[(lastColon + 1)..].Equals("latest", StringComparison.OrdinalIgnoreCase);
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
        (TestRuntimeInstructionPattern().IsMatch(content) ||
         (!RuntimeInstructionPattern().IsMatch(content) &&
          BuildInstructionPattern().IsMatch(content)));

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

    [GeneratedRegex(@"(?mi)^\s*USER\s+(?<user>\S+)")]
    private static partial Regex UserPattern();

    [GeneratedRegex(@"^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\})$")]
    private static partial Regex VariableReferencePattern();

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

    [GeneratedRegex(@"(?mi)^\s*HEALTHCHECK\s+NONE\b")]
    private static partial Regex HealthcheckNonePattern();

    [GeneratedRegex(@"(?mi)^\s*FROM\s+(?<image>\S+)")]
    private static partial Regex FromInstructionPattern();

    [GeneratedRegex(@"\\\s*\r?\n\s*")]
    private static partial Regex DockerLineContinuationPattern();

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

    private static void CheckRemoteInstallerPipe(string content, string relativePath, List<Finding> findings)
    {
        var matches = RemoteInstallerPipePattern().Matches(content);
        foreach (Match match in matches)
        {
            findings.Add(new Finding(
                "TRUST-DOCKER012",
                "Dockerfile pipes remote installer to shell",
                AnalysisCategory.Containers,
                Severity.High,
                Confidence.High,
                "A RUN instruction downloads remote content and pipes it into a shell.",
                [new Evidence("dockerfile", "Remote installer output is piped directly to a shell.", relativePath, GetLineNumber(content, match.Index), match.Value.Trim())],
                new Recommendation("Download release artifacts with pinned checksums or signatures instead of piping network content directly to a shell.")));
            break;
        }
    }

    [GeneratedRegex(@"(?mi)^\s*ADD\s+(?<src>\S+)\s+\S+")]
    private static partial Regex AddInstructionPattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.*\bsudo\b")]
    private static partial Regex SudoPattern();

    [GeneratedRegex(@"(?mi)^\s*EXPOSE\s+(?<start>\d+)-(?<end>\d+)")]
    private static partial Regex ExposePortRangePattern();

    [GeneratedRegex(@"(?mi)^\s*RUN\s+.*\b(?:curl|wget)\b.*\|\s*(?:/bin/)?(?:sh|bash)\b")]
    private static partial Regex RemoteInstallerPipePattern();

    private sealed record DockerfileCandidate(string FullPath, string RelativePath, bool IsBuildSupport);

    private sealed record DockerfileStage(string BaseImage, string Content);
}

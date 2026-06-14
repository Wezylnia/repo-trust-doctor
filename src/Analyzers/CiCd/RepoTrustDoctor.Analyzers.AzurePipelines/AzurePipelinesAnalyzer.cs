using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.AzurePipelines;

public sealed partial class AzurePipelinesAnalyzer : IRepositoryAnalyzer
{
    private static readonly string[] FileNames =
    [
        "azure-pipelines.yml",
        "azure-pipelines.yaml"
    ];

    private static readonly string[] PipelineDirectories =
    [
        ".azure-pipelines",
        "azure-pipelines",
        "build/azure-pipelines",
        ".azure/pipelines",
        ".pipelines"
    ];

    public string Id => "azure-pipelines";

    public string DisplayName => "Azure Pipelines Security";

    public AnalysisCategory Category => AnalysisCategory.CiCd;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Fast;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-AZP001", "Azure pipeline script uses untrusted variable expansion", AnalysisCategory.CiCd, Severity.High, Confidence.Medium,
            "A script step interpolates attacker-controlled PR variables.", "Avoid interpolating PR-controlled variables in script blocks. Use environment variables or template expressions instead."),
        new("TRUST-AZP002", "Azure pipeline checkout persists credentials", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "checkout: self has persistCredentials: true.", "Set persistCredentials: false unless later steps truly need repository write credentials."),
        new("TRUST-AZP003", "Azure pipeline container image uses latest or no tag", AnalysisCategory.CiCd, Severity.Medium, Confidence.High,
            "A container or service image uses :latest or no tag.", "Pin container images to specific versions or digests for reproducible CI runs."),
        new("TRUST-AZP004", "Azure pipeline uses self-hosted pool", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium,
            "The pipeline uses a self-hosted agent pool.", "Isolate agents, rotate tokens, and limit workspace reuse for self-hosted pools."),
        new("TRUST-AZP005", "Azure pipeline publishes broad artifact path", AnalysisCategory.CiCd, Severity.Low, Confidence.Medium,
            "A publish task uses a broad path that may include the entire workspace.", "Narrow artifact publish paths to specific build output directories."),
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var file in EnumeratePipelineFiles(context.RepositoryPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RepositoryFileSystem.CanReadAsText(file))
                continue;

            var content = await File.ReadAllTextAsync(file, cancellationToken);
            var relativePath = Path.GetRelativePath(context.RepositoryPath, file);

            CheckPrVariablesInScripts(content, relativePath, findings);
            CheckPersistCredentials(content, relativePath, findings);
            CheckLatestContainerImage(content, relativePath, findings);
            CheckSelfHostedPool(content, relativePath, findings);
            CheckBroadArtifactPath(content, relativePath, findings);
        }

        return AnalyzerResult.Completed(findings);
    }

    // ── AZP001: untrusted PR variables in scripts ─────────────────────

    private static void CheckPrVariablesInScripts(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!ScriptStepPattern().IsMatch(lines[i]))
            {
                continue;
            }

            if (PrVariablePattern().IsMatch(lines[i]))
            {
                AddPrVariableFinding(relativePath, i + 1, findings);
                continue;
            }

            if (!BlockScalarScriptPattern().IsMatch(lines[i]))
            {
                continue;
            }

            var contentIndent = FindBlockContentIndent(lines, i + 1);
            if (contentIndent is null)
            {
                continue;
            }

            for (var cursor = i + 1; cursor < lines.Length; cursor++)
            {
                if (string.IsNullOrWhiteSpace(lines[cursor]))
                {
                    continue;
                }

                if (GetIndentation(lines[cursor]) < contentIndent)
                {
                    break;
                }

                if (PrVariablePattern().IsMatch(lines[cursor]))
                {
                    AddPrVariableFinding(relativePath, cursor + 1, findings);
                    break;
                }
            }
        }
    }

    private static int? FindBlockContentIndent(string[] lines, int startIndex)
    {
        for (var index = startIndex; index < lines.Length; index++)
        {
            if (!string.IsNullOrWhiteSpace(lines[index]))
            {
                return GetIndentation(lines[index]);
            }
        }

        return null;
    }

    private static void AddPrVariableFinding(
        string relativePath,
        int lineNumber,
        ICollection<Finding> findings)
    {
        findings.Add(CreateFinding("TRUST-AZP001",
            "Azure pipeline script uses untrusted variable",
            Severity.High,
            relativePath,
            "Script step interpolates a PR-controlled variable.",
            lineNumber,
            Confidence.Medium));
    }

    // ── AZP002: persistCredentials ────────────────────────────────────

    private static void CheckPersistCredentials(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!CheckoutSelfPattern().IsMatch(lines[i]))
                continue;

            var baseIndent = GetIndentation(lines[i]);
            for (var cursor = i + 1; cursor < lines.Length; cursor++)
            {
                if (string.IsNullOrWhiteSpace(lines[cursor]))
                    continue;

                if (GetIndentation(lines[cursor]) <= baseIndent)
                    break;

                if (!PersistCredentialsTruePattern().IsMatch(lines[cursor]))
                    continue;

                findings.Add(CreateFinding("TRUST-AZP002",
                    "Checkout persists credentials",
                    Severity.Medium,
                    relativePath,
                    "checkout: self has persistCredentials: true. Set false unless write access is needed.",
                    cursor + 1));
                break;
            }
        }
    }

    // ── AZP003: latest container image ────────────────────────────────

    private static void CheckLatestContainerImage(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in AzureLatestImagePattern().Matches(content))
        {
            var image = match.Groups["image"].Value;
            // Skip digest-pinned images
            if (image.Contains("@sha256:", StringComparison.OrdinalIgnoreCase))
                continue;

            findings.Add(CreateFinding("TRUST-AZP003",
                "Azure pipeline uses unpinned container image",
                Severity.Medium,
                relativePath,
                $"Container image '{image}' uses :latest or no tag.",
                GetLineNumber(content, match.Index)));
        }
    }

    // ── AZP004: self-hosted pool ──────────────────────────────────────

    private static void CheckSelfHostedPool(string content, string relativePath, List<Finding> findings)
    {
        var seen = new HashSet<string>();
        var lines = SplitLines(content);
        for (var i = 0; i < lines.Length; i++)
        {
            var inline = InlinePoolPattern().Match(lines[i]);
            if (inline.Success)
            {
                var pool = inline.Groups["pool"].Value.Trim();
                if (IsHostedPool(pool) || !seen.Add(pool))
                    continue;

                findings.Add(CreateFinding("TRUST-AZP004",
                    "Self-hosted agent pool",
                    Severity.Low,
                    relativePath,
                    $"Uses self-hosted pool '{pool}'. Isolate agents and rotate tokens.",
                    i + 1,
                    Confidence.Medium));

                continue;
            }

            if (!PoolHeaderPattern().IsMatch(lines[i]))
                continue;

            var baseIndent = GetIndentation(lines[i]);
            var poolName = "";
            var hasVmImage = false;
            for (var cursor = i + 1; cursor < lines.Length; cursor++)
            {
                if (string.IsNullOrWhiteSpace(lines[cursor]))
                    continue;

                if (GetIndentation(lines[cursor]) <= baseIndent)
                    break;

                if (VmImagePattern().IsMatch(lines[cursor]))
                    hasVmImage = true;

                var name = PoolNamePattern().Match(lines[cursor]);
                if (name.Success)
                    poolName = name.Groups["pool"].Value.Trim();
            }

            if (!hasVmImage && !string.IsNullOrWhiteSpace(poolName) && seen.Add(poolName))
            {
                findings.Add(CreateFinding("TRUST-AZP004",
                    "Self-hosted agent pool",
                    Severity.Low,
                    relativePath,
                    $"Uses self-hosted pool '{poolName}'. Isolate agents and rotate tokens.",
                    i + 1,
                    Confidence.Medium));
            }
        }
    }

    // ── AZP005: broad artifact publish path ───────────────────────────

    private static void CheckBroadArtifactPath(string content, string relativePath, List<Finding> findings)
    {
        foreach (Match match in BroadArtifactPathPattern().Matches(content))
        {
            var path = match.Groups["path"].Value.Trim();
            var normalized = path.TrimEnd('/', '*');

            if (IsExpression(path))
                continue;

            // Skip narrow paths
            if (normalized is "dist" or "build/output" or "artifacts" ||
                normalized.Contains('/') && !normalized.Contains("System.DefaultWorkingDirectory", StringComparison.OrdinalIgnoreCase))
                continue;

            findings.Add(CreateFinding("TRUST-AZP005",
                "Broad artifact publish path",
                Severity.Low,
                relativePath,
                $"Publishes broad path '{path}'. Narrow to specific output directories.",
                GetLineNumber(content, match.Index),
                Confidence.Medium));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private static Finding CreateFinding(string ruleId, string title, Severity severity, string filePath, string evidence, int? lineNumber = null, Confidence confidence = Confidence.High)
    {
        return new Finding(ruleId, title, AnalysisCategory.CiCd, severity, confidence, title,
            [new Evidence("azure-pipelines", evidence, filePath, lineNumber)],
            new Recommendation("Review the Azure Pipelines configuration and apply the recommended fix."));
    }

    private static string[] SplitLines(string content) =>
        content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');

    private static IEnumerable<string> EnumeratePipelineFiles(string root)
    {
        var seen = new HashSet<string>(
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var pattern in FileNames)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(root, pattern))
            {
                if (seen.Add(Path.GetFullPath(file)))
                    yield return file;
            }
        }

        foreach (var relativeDirectory in PipelineDirectories)
        {
            var directory = Path.Combine(root, relativeDirectory.Replace('/', Path.DirectorySeparatorChar));
            if (!Directory.Exists(directory))
                continue;

            foreach (var file in RepositoryFileSystem.EnumerateFiles(directory, "*.yml")
                         .Concat(RepositoryFileSystem.EnumerateFiles(directory, "*.yaml")))
            {
                if (seen.Add(Path.GetFullPath(file)))
                    yield return file;
            }
        }
    }

    private static bool IsExpression(string value) =>
        value.Contains("${{", StringComparison.Ordinal) ||
        value.Contains("$(", StringComparison.Ordinal) ||
        value.Contains("$[", StringComparison.Ordinal);

    private static int GetIndentation(string line)
    {
        var count = 0;
        foreach (var c in line)
        {
            if (c == ' ') count++;
            else if (c == '\t') count += 4;
            else break;
        }

        return count;
    }

    private static bool IsHostedPool(string pool) =>
        pool.Equals("server", StringComparison.OrdinalIgnoreCase) ||
        pool.Contains("ubuntu-latest", StringComparison.OrdinalIgnoreCase) ||
        pool.Contains("windows-latest", StringComparison.OrdinalIgnoreCase) ||
        pool.Contains("macos-latest", StringComparison.OrdinalIgnoreCase);

    private static int GetLineNumber(string content, int matchIndex)
    {
        var line = 1;
        for (var i = 0; i < matchIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }

    // ── Patterns ──────────────────────────────────────────────────────

    [GeneratedRegex(@"(?m)^\s*(?:-\s*)?(?:script|bash|pwsh|powershell)\s*:")]
    private static partial Regex ScriptStepPattern();

    [GeneratedRegex(@"^\s*(?:-\s*)?(?:script|bash|pwsh|powershell)\s*:\s*[|>][-+]?\s*$")]
    private static partial Regex BlockScalarScriptPattern();

    [GeneratedRegex(@"\$\((System\.PullRequest\.(SourceBranch|SourceRepositoryURI)|Build\.SourceBranch(Name)?)\)")]
    private static partial Regex PrVariablePattern();

    [GeneratedRegex(@"^\s*-\s*checkout\s*:\s*self\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex CheckoutSelfPattern();

    [GeneratedRegex(@"^\s*persistCredentials\s*:\s*true\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex PersistCredentialsTruePattern();

    [GeneratedRegex(@"(?:container|image)\s*:\s*['""]?(?<image>[^'""\s]+(?::latest|$))['""]?", RegexOptions.IgnoreCase)]
    private static partial Regex AzureLatestImagePattern();

    [GeneratedRegex(@"^\s*pool\s*:\s*(?<pool>[A-Za-z0-9_. -]+)\s*$")]
    private static partial Regex InlinePoolPattern();

    [GeneratedRegex(@"^\s*pool\s*:\s*$")]
    private static partial Regex PoolHeaderPattern();

    [GeneratedRegex(@"^\s*name\s*:\s*(?<pool>[A-Za-z0-9_. -]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex PoolNamePattern();

    [GeneratedRegex(@"^\s*vmImage\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex VmImagePattern();

    [GeneratedRegex(@"(?:PublishBuildArtifacts|PublishPipelineArtifact)@\d+[\s\S]*?(?:[Pp]athto[Pp]ublish|targetPath)\s*:\s*['""]?(?<path>[^'""\n]+)['""]?",
        RegexOptions.IgnoreCase)]
    private static partial Regex BroadArtifactPathPattern();
}

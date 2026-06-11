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

        foreach (var pattern in FileNames)
        {
            foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, pattern))
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
        }

        return AnalyzerResult.Completed(findings);
    }

    // ── AZP001: untrusted PR variables in scripts ─────────────────────

    private static void CheckPrVariablesInScripts(string content, string relativePath, List<Finding> findings)
    {
        var lines = SplitLines(content);
        bool inScriptBlock = false;

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            {
                if (inScriptBlock && line.Length == 0)
                    continue;
                inScriptBlock = false;
                continue;
            }

            if (ScriptStepPattern().IsMatch(line))
            {
                inScriptBlock = true;
                // Check same line for PR variables (inline script)
                if (PrVariablePattern().IsMatch(line))
                {
                    findings.Add(CreateFinding("TRUST-AZP001",
                        "Azure pipeline script uses untrusted variable",
                        Severity.High,
                        relativePath,
                        "Script step interpolates a PR-controlled variable.",
                        i + 1,
                        Confidence.Medium));
                    inScriptBlock = false;
                }
                continue;
            }

            if (inScriptBlock && PrVariablePattern().IsMatch(line))
            {
                findings.Add(CreateFinding("TRUST-AZP001",
                    "Azure pipeline script uses untrusted variable",
                    Severity.High,
                    relativePath,
                    "Script step interpolates a PR-controlled variable.",
                    i + 1,
                    Confidence.Medium));
                inScriptBlock = false;
            }
        }
    }

    // ── AZP002: persistCredentials ────────────────────────────────────

    private static void CheckPersistCredentials(string content, string relativePath, List<Finding> findings)
    {
        if (PersistCredentialsPattern().IsMatch(content))
        {
            findings.Add(CreateFinding("TRUST-AZP002",
                "Checkout persists credentials",
                Severity.Medium,
                relativePath,
                "checkout: self has persistCredentials: true. Set false unless write access is needed.",
                GetLineNumber(content, content.IndexOf("persistCredentials", StringComparison.OrdinalIgnoreCase))));
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
        // Skip if vmImage is used (hosted agent)
        if (content.Contains("vmImage", StringComparison.OrdinalIgnoreCase))
            return;

        var seen = new HashSet<string>();
        foreach (Match match in SelfHostedPoolPattern().Matches(content))
        {
            var pool = match.Groups["pool"].Value.Trim();
            if (seen.Add(pool))
            {
                findings.Add(CreateFinding("TRUST-AZP004",
                    "Self-hosted agent pool",
                    Severity.Low,
                    relativePath,
                    $"Uses self-hosted pool '{pool}'. Isolate agents and rotate tokens.",
                    GetLineNumber(content, match.Index),
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

    [GeneratedRegex(@"\$\((System\.PullRequest\.(SourceBranch|SourceRepositoryURI)|Build\.SourceBranch(Name)?)\)")]
    private static partial Regex PrVariablePattern();

    [GeneratedRegex(@"persistCredentials\s*:\s*true", RegexOptions.IgnoreCase)]
    private static partial Regex PersistCredentialsPattern();

    [GeneratedRegex(@"(?:container|image)\s*:\s*['""]?(?<image>[^'""\s]+(?::latest|$))['""]?", RegexOptions.IgnoreCase)]
    private static partial Regex AzureLatestImagePattern();

    [GeneratedRegex(@"(?m)^\s*(?:pool\s*:\s*(?<pool>\w+)|pool\s*:\s*\n\s*name\s*:\s*(?<pool>\w+))")]
    private static partial Regex SelfHostedPoolPattern();

    [GeneratedRegex(@"(?:PublishBuildArtifacts|PublishPipelineArtifact)@\d+[\s\S]*?(?:[Pp]athto[Pp]ublish|targetPath)\s*:\s*['""]?(?<path>[^'""\n]+)['""]?",
        RegexOptions.IgnoreCase)]
    private static partial Regex BroadArtifactPathPattern();
}

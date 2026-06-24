using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.Repository;

public sealed class GitHubMetadataAnalyzer : IRepositoryAnalyzer
{
    private static readonly TimeSpan InactiveWarnThreshold = TimeSpan.FromDays(180);
    private static readonly TimeSpan InactiveMediumThreshold = TimeSpan.FromDays(365);
    private static readonly TimeSpan NoReleaseWarnDays = TimeSpan.FromDays(365);
    private static readonly TimeSpan NoReleaseMediumDays = TimeSpan.FromDays(730);

    private static readonly string[] ChecksumLikeAssetNames =
    [
        "sha256", "sha512", "checksums", ".sha256", ".sha512",
        "SHA256SUMS", "checksums.txt", "checksum", "sha256sums", "sha256sum"
    ];

    private static readonly string[] DependencyAutomationConfigs =
    [
        ".github/dependabot.yml", ".github/dependabot.yaml",
        "renovate.json", ".renovaterc", ".renovaterc.json", ".github/renovate.json"
    ];

    private readonly IGitHubRepositoryMetadataClient? client;
    private readonly string repositoryPath;

    // For testing: directly inject artifact
    internal GitHubMetadataAnalyzer(IGitHubRepositoryMetadataClient? client, string repositoryPath = "")
    {
        this.client = client;
        this.repositoryPath = repositoryPath;
    }

    public GitHubMetadataAnalyzer() : this(null, "")
    {
    }

    public string Id => "github.metadata";

    public string DisplayName => "GitHub Repository Metadata";

    public AnalysisCategory Category => AnalysisCategory.RepositoryHealth;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [];

    public IReadOnlyCollection<string> ProducesArtifacts => [GitHubRepositoryMetadataArtifact.ArtifactKey];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.NetworkLookup;

    public TimeSpan Timeout => TimeSpan.FromSeconds(15);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-GHM001", "GitHub repository is archived or disabled",
            AnalysisCategory.RepositoryHealth, Severity.High, Confidence.High,
            "The GitHub repository is archived or disabled, which may indicate the project is no longer maintained.",
            "Review whether this repository is still suitable for production dependency or operational use."),
        new("TRUST-GHM002", "Repository appears inactive",
            AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium,
            "The repository appears inactive based on the latest observed commit or push timestamp.",
            "Review project maintenance status, recent issues, forks, and alternatives before relying on it."),
        new("TRUST-GHM003", "No recent release activity",
            AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium,
            "The repository has no recent GitHub release activity.",
            "Review whether releases are published through another channel, and whether consumers can identify stable versions."),
        new("TRUST-GHM004", "Latest release lacks checksum-like asset evidence",
            AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium,
            "The latest GitHub release has downloadable assets but no checksum-like asset name was observed.",
            "Publish checksum files or equivalent integrity evidence for release artifacts."),
        new("TRUST-GHM005", "Default branch CI is currently failing",
            AnalysisCategory.RepositoryHealth, Severity.Medium, Confidence.High,
            "The latest observed default branch CI run did not complete successfully.",
            "Review the default branch workflow failure before trusting the current repository state."),
        new("TRUST-GHM006", "Default branch protection evidence is missing or weak",
            AnalysisCategory.RepositoryHealth, Severity.Medium, Confidence.Medium,
            "Default branch protection was not observed for the GitHub repository.",
            "Enable branch protection, required reviews, and required status checks for the default branch."),
        new("TRUST-GHM007", "Dependency update automation was not observed",
            AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Medium,
            "No common dependency update automation configuration was observed.",
            "Consider Dependabot, Renovate, or an equivalent dependency update workflow."),
        new("TRUST-GHM008", "Stale open pull requests or issues may indicate maintenance backlog",
            AnalysisCategory.RepositoryHealth, Severity.Low, Confidence.Low,
            "Open issue or pull request activity may indicate a maintenance backlog.",
            "Review project maintenance activity before relying on the repository.")
    ];

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        GitHubRepositoryMetadataArtifact? artifact = null;

        // Try to fetch GitHub metadata
        if (client is not null)
        {
            var (owner, repo) = TryParseGitHubTarget(context.Target);
            if (owner is not null && repo is not null)
            {
                try
                {
                    artifact = await client.FetchAsync(owner, repo, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // Network failure: proceed with no metadata
                }
            }
        }

        if (artifact is null)
        {
            // Produce a minimal artifact with no metadata
            artifact = new GitHubRepositoryMetadataArtifact(
                Repository: null,
                Activity: null,
                Popularity: null,
                Releases: null,
                Ci: null,
                Protection: null,
                Metrics: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["github.metadata.available"] = "false"
                });

            var warning = client is null
                ? "GitHub metadata client was not configured; GitHub repository checks were skipped."
                : "GitHub metadata was not available for this target.";

            return new AnalyzerResult(
                ModuleStatus.Completed,
                [],
                [new AnalyzerArtifact(GitHubRepositoryMetadataArtifact.ArtifactKey, artifact)],
                artifact.Metrics,
                [warning]);
        }

        // Populate metrics
        var metrics = new Dictionary<string, string>(artifact.Metrics, StringComparer.OrdinalIgnoreCase)
        {
            ["github.metadata.available"] = "true",
            ["github.metadata.evidence_state"] = artifact.Protection?.EvidenceState ?? "unknown",
            ["github.metadata.release.count"] = (artifact.Releases?.ReleaseCount ?? 0).ToString(),
            ["github.metadata.workflow.recent_failed.count"] = (artifact.Ci?.RecentFailedDefaultBranchRuns ?? 0).ToString(),
            ["github.metadata.workflow.recent_successful.count"] = (artifact.Ci?.RecentSuccessfulDefaultBranchRuns ?? 0).ToString()
        };

        // --- GHM001: Archived or disabled ---
        if (artifact.Repository is { IsArchived: true } or { IsDisabled: true })
        {
            var fullName = artifact.Repository.FullName ?? "unknown";
            findings.Add(new Finding(
                "TRUST-GHM001",
                "GitHub repository is archived or disabled",
                AnalysisCategory.RepositoryHealth,
                Severity.High,
                Confidence.High,
                $"The GitHub repository `{fullName}` is archived or disabled. This may indicate that the project is no longer maintained.",
                [new Evidence("github-metadata", $"Repository `{fullName}`: archived={artifact.Repository.IsArchived}, disabled={artifact.Repository.IsDisabled}.")],
                new Recommendation("Review whether this repository is still suitable for production dependency or operational use."),
                IdentityKey: $"ghm001|{fullName.ToLowerInvariant()}"));
        }

        // --- GHM002: Inactive repository ---
        var lastActivity = artifact.Activity?.LatestCommitAt ?? artifact.Activity?.PushedAt;
        if (lastActivity.HasValue)
        {
            var age = DateTimeOffset.UtcNow - lastActivity.Value;
            if (age > InactiveMediumThreshold)
            {
                findings.Add(CreateGhmFinding("TRUST-GHM002",
                    "Repository appears inactive",
                    Severity.Medium,
                    Confidence.Medium,
                    age,
                    lastActivity.Value,
                    artifact.Repository?.FullName ?? "unknown"));
            }
            else if (age > InactiveWarnThreshold)
            {
                findings.Add(CreateGhmFinding("TRUST-GHM002",
                    "Repository appears inactive",
                    Severity.Low,
                    Confidence.Medium,
                    age,
                    lastActivity.Value,
                    artifact.Repository?.FullName ?? "unknown"));
            }
        }

        // --- GHM003: No recent release ---
        var latestReleaseDate = artifact.Releases?.LatestReleasePublishedAt ?? artifact.Releases?.LatestTagCommitAt;
        if (latestReleaseDate.HasValue)
        {
            var releaseAge = DateTimeOffset.UtcNow - latestReleaseDate.Value;
            if (releaseAge > NoReleaseMediumDays)
            {
                findings.Add(CreateGhmReleaseFinding("TRUST-GHM003",
                    "No recent release activity",
                    Severity.Medium,
                    Confidence.Medium,
                    releaseAge,
                    latestReleaseDate.Value,
                    artifact.Repository?.FullName ?? "unknown"));
            }
            else if (releaseAge > NoReleaseWarnDays)
            {
                findings.Add(CreateGhmReleaseFinding("TRUST-GHM003",
                    "No recent release activity",
                    Severity.Low,
                    Confidence.Medium,
                    releaseAge,
                    latestReleaseDate.Value,
                    artifact.Repository?.FullName ?? "unknown"));
            }
        }

        // --- GHM004: No checksum-like asset ---
        if (artifact.Releases is { LatestReleaseHasAssets: true, LatestReleaseHasChecksumLikeAsset: false })
        {
            var fullName = artifact.Repository?.FullName ?? "unknown";
            var tag = artifact.Releases.LatestReleaseTag ?? "unknown";
            findings.Add(new Finding(
                "TRUST-GHM004",
                "Latest release lacks checksum-like asset evidence",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Medium,
                $"The latest GitHub release `{tag}` has assets but no checksum-like asset name was observed.",
                [new Evidence("github-release", $"Release `{tag}` has assets but no checksum-like asset name.")],
                new Recommendation("Publish checksum files or equivalent integrity evidence for release artifacts."),
                IdentityKey: $"ghm004|{fullName.ToLowerInvariant()}|{tag.ToLowerInvariant()}"));
        }

        // --- GHM005: Default branch CI failing ---
        if (artifact.Ci?.LatestDefaultBranchWorkflowConclusion is { } conclusion)
        {
            var failedConclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "failure", "timed_out", "cancelled", "startup_failure", "action_required"
            };
            if (failedConclusions.Contains(conclusion))
            {
                var fullName = artifact.Repository?.FullName ?? "unknown";
                var branch = artifact.Repository?.DefaultBranch ?? "main";
                findings.Add(new Finding(
                    "TRUST-GHM005",
                    "Default branch CI is currently failing",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Medium,
                    Confidence.High,
                    $"The latest observed default branch CI run did not complete successfully (conclusion: {conclusion}).",
                    [new Evidence("github-ci", $"Default branch `{branch}` workflow conclusion: {conclusion}.")],
                    new Recommendation("Review the default branch workflow failure before trusting the current repository state."),
                    IdentityKey: $"ghm005|{fullName.ToLowerInvariant()}|{branch.ToLowerInvariant()}"));
            }
        }

        // --- GHM006: Branch protection ---
        if (artifact.Protection is { } protection)
        {
            var fullName = artifact.Repository?.FullName ?? "unknown";
            var branch = artifact.Repository?.DefaultBranch ?? "main";

            if (protection.DefaultBranchProtected == false)
            {
                findings.Add(new Finding(
                    "TRUST-GHM006",
                    "Default branch protection evidence is missing or weak",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Medium,
                    Confidence.High,
                    $"Default branch protection was not observed for the GitHub repository `{fullName}`.",
                    [new Evidence("github-protection", $"Default branch `{branch}` is not protected.")],
                    new Recommendation("Enable branch protection, required reviews, and required status checks for the default branch."),
                    IdentityKey: $"ghm006|{fullName.ToLowerInvariant()}|{branch.ToLowerInvariant()}"));
            }
            else if (protection.DefaultBranchProtected is null &&
                     protection.EvidenceState is "permission-denied" or "not-available")
            {
                findings.Add(new Finding(
                    "TRUST-GHM006",
                    "Default branch protection evidence is missing or weak",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Low,
                    $"Default branch protection could not be verified from available GitHub metadata for `{fullName}`.",
                    [new Evidence("github-protection", $"Evidence state: {protection.EvidenceState}.")],
                    new Recommendation("Enable branch protection, required reviews, and required status checks for the default branch."),
                    IdentityKey: $"ghm006|{fullName.ToLowerInvariant()}|{branch.ToLowerInvariant()}"));
            }
        }

        // --- GHM007: Dependency update automation ---
        if (!string.IsNullOrWhiteSpace(repositoryPath))
        {
            var hasAutomation = DependencyAutomationConfigs.Any(config =>
                File.Exists(Path.Combine(repositoryPath, config)));
            if (!hasAutomation)
            {
                findings.Add(new Finding(
                    "TRUST-GHM007",
                    "Dependency update automation was not observed",
                    AnalysisCategory.RepositoryHealth,
                    Severity.Low,
                    Confidence.Medium,
                    "No common dependency update automation configuration was observed.",
                    [new Evidence("repository-file", "No .github/dependabot.yml, renovate.json, or equivalent configuration found.")],
                    new Recommendation("Consider Dependabot, Renovate, or an equivalent dependency update workflow."),
                    IdentityKey: "ghm007|repository-root"));
            }
        }

        // --- GHM008: Stale open issues/PRs (optional) ---
        if (artifact.Activity is { OpenIssueCount: { } issueCount, OpenPullRequestCount: { } prCount } &&
            (issueCount > 50 || prCount > 20))
        {
            var fullName = artifact.Repository?.FullName ?? "unknown";
            findings.Add(new Finding(
                "TRUST-GHM008",
                "Stale open pull requests or issues may indicate maintenance backlog",
                AnalysisCategory.RepositoryHealth,
                Severity.Low,
                Confidence.Low,
                $"Repository `{fullName}` has {issueCount} open issues and {prCount} open pull requests.",
                [new Evidence("github-activity", $"Open issues: {issueCount}, open PRs: {prCount}.")],
                new Recommendation("Review project maintenance activity before relying on the repository."),
                IdentityKey: $"ghm008|{fullName.ToLowerInvariant()}"));
        }

        // IMPORTANT: popularity metrics (stars, forks, watchers) never produce findings
        return AnalyzerResult.Completed(
            findings,
            artifacts: [new AnalyzerArtifact(GitHubRepositoryMetadataArtifact.ArtifactKey, artifact with { Metrics = metrics })],
            metrics: metrics);
    }

    private static Finding CreateGhmFinding(
        string ruleId, string title, Severity severity, Confidence confidence,
        TimeSpan age, DateTimeOffset lastActivity, string fullName)
    {
        var days = (int)age.TotalDays;
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.RepositoryHealth,
            severity,
            confidence,
            $"The repository `{fullName}` appears inactive: last observed activity was approximately {days} days ago.",
            [new Evidence("github-activity", $"Last activity: {lastActivity:yyyy-MM-dd} (approximately {days} days ago).")],
            new Recommendation("Review project maintenance status, recent issues, forks, and alternatives before relying on it."),
            IdentityKey: $"ghm002|{fullName.ToLowerInvariant()}");
    }

    private static Finding CreateGhmReleaseFinding(
        string ruleId, string title, Severity severity, Confidence confidence,
        TimeSpan age, DateTimeOffset lastRelease, string fullName)
    {
        var days = (int)age.TotalDays;
        return new Finding(
            ruleId,
            title,
            AnalysisCategory.RepositoryHealth,
            severity,
            confidence,
            $"The repository `{fullName}` has no recent GitHub release activity: last release was approximately {days} days ago.",
            [new Evidence("github-release", $"Last release: {lastRelease:yyyy-MM-dd} (approximately {days} days ago).")],
            new Recommendation("Review whether releases are published through another channel, and whether consumers can identify stable versions."),
            IdentityKey: $"ghm003|{fullName.ToLowerInvariant()}");
    }

    internal static (string? owner, string? repo) TryParseGitHubTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return (null, null);
        }

        // Handle https://github.com/owner/repo format
        if (target.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("http://github.com/", StringComparison.OrdinalIgnoreCase))
        {
            var path = target.Substring(target.IndexOf("github.com/", StringComparison.OrdinalIgnoreCase) + 11);
            path = path.TrimEnd('/');
            if (path.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(0, path.Length - 4);
            }
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return (parts[0], parts[1]);
            }
        }

        // Handle git@github.com:owner/repo.git format
        if (target.StartsWith("git@github.com:", StringComparison.OrdinalIgnoreCase))
        {
            var path = target.Substring(15);
            if (path.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(0, path.Length - 4);
            }
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return (parts[0], parts[1]);
            }
        }

        return (null, null);
    }

    internal static bool IsChecksumLikeAssetName(string assetName)
    {
        if (string.IsNullOrWhiteSpace(assetName))
        {
            return false;
        }

        return ChecksumLikeAssetNames.Any(pattern =>
            assetName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }
}

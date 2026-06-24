namespace RepoTrustDoctor.Analysis.Abstractions;

/// <summary>
/// Structured GitHub repository metadata collected from the GitHub API.
/// All fields are nullable; null means the data was not available.
/// </summary>
public sealed record GitHubRepositoryMetadataArtifact(
    GitHubRepositoryIdentity? Repository,
    GitHubRepositoryActivity? Activity,
    GitHubRepositoryPopularity? Popularity,
    GitHubRepositoryReleaseSnapshot? Releases,
    GitHubRepositoryCiSnapshot? Ci,
    GitHubRepositoryProtectionSnapshot? Protection,
    IReadOnlyDictionary<string, string> Metrics)
{
    public const string ArtifactKey = "github.repository-metadata";
}

public sealed record GitHubRepositoryIdentity(
    string? FullName,
    string? HtmlUrl,
    string? DefaultBranch,
    string? Visibility,
    bool? IsFork,
    bool? IsArchived,
    bool? IsDisabled);

public sealed record GitHubRepositoryActivity(
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt,
    DateTimeOffset? PushedAt,
    DateTimeOffset? LatestCommitAt,
    int? OpenIssueCount,
    int? OpenPullRequestCount);

public sealed record GitHubRepositoryPopularity(
    int? StargazerCount,
    int? ForkCount,
    int? WatcherCount);

public sealed record GitHubRepositoryReleaseSnapshot(
    int? ReleaseCount,
    string? LatestReleaseName,
    string? LatestReleaseTag,
    DateTimeOffset? LatestReleasePublishedAt,
    DateTimeOffset? LatestTagCommitAt,
    bool? LatestReleaseHasAssets,
    bool? LatestReleaseHasChecksumLikeAsset);

public sealed record GitHubRepositoryCiSnapshot(
    string? LatestDefaultBranchWorkflowConclusion,
    DateTimeOffset? LatestDefaultBranchWorkflowRunAt,
    int? RecentFailedDefaultBranchRuns,
    int? RecentSuccessfulDefaultBranchRuns);

public sealed record GitHubRepositoryProtectionSnapshot(
    bool? DefaultBranchProtected,
    bool? RequiresStatusChecks,
    bool? RequiresPullRequestReviews,
    bool? AllowsForcePushes,
    bool? AllowsDeletions,
    string EvidenceState);

/// <summary>
/// Contract for fetching GitHub repository metadata.
/// Implementations must be safe: bounded, cancellable, fail gracefully.
/// </summary>
public interface IGitHubRepositoryMetadataClient
{
    Task<GitHubRepositoryMetadataArtifact?> FetchAsync(
        string owner,
        string repo,
        CancellationToken cancellationToken);
}

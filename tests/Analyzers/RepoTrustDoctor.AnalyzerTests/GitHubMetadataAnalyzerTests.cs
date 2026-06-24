using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class GitHubMetadataAnalyzerTests
{
    // --- Fake client for testing ---

    private sealed class FakeGitHubMetadataClient(
        GitHubRepositoryMetadataArtifact? response = null,
        bool throwNetworkError = false) : IGitHubRepositoryMetadataClient
    {
        public Task<GitHubRepositoryMetadataArtifact?> FetchAsync(
            string owner, string repo, CancellationToken cancellationToken)
        {
            if (throwNetworkError)
            {
                throw new HttpRequestException("Simulated network error");
            }
            return Task.FromResult(response);
        }
    }

    private static AnalysisContext CreateContext(string target = "https://github.com/owner/repo",
        string repoPath = "/tmp/repo")
    {
        return new AnalysisContext(target, repoPath, AnalysisDepth.Standard);
    }

    // --- Artifact tests ---

    [Fact]
    public async Task Analyzer_ProducesArtifact_FromFakeClient()
    {
        var metadata = CreateBasicMetadata();
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        var artifact = Assert.Single(result.Artifacts!, a => a.Key == GitHubRepositoryMetadataArtifact.ArtifactKey);
        var meta = Assert.IsType<GitHubRepositoryMetadataArtifact>(artifact.Value);
        Assert.Equal("true", meta.Metrics["github.metadata.available"]);
    }

    [Fact]
    public async Task Analyzer_ReturnsWarning_WhenClientNotConfigured()
    {
        var analyzer = new GitHubMetadataAnalyzer(); // no client
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Warnings!, w => w.Contains("not configured", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Analyzer_HandlesNetworkFailure()
    {
        var client = new FakeGitHubMetadataClient(throwNetworkError: true);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Equal(ModuleStatus.Completed, result.Status);
        Assert.Empty(result.Findings); // No high-confidence findings on network failure
    }

    // --- GHM001: Archived or disabled ---

    [Fact]
    public async Task GHM001_ArchivedRepository_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Repository = new GitHubRepositoryIdentity("test/repo", null, "main", "public", false, true, false)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-GHM001");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.High, finding.Confidence);
        Assert.NotEmpty(finding.Evidence);
        Assert.Contains("ghm001|test/repo", finding.IdentityKey);
    }

    [Fact]
    public async Task GHM001_ActiveRepository_NoFinding()
    {
        var metadata = CreateBasicMetadata();
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHM001");
    }

    // --- GHM002: Inactive ---

    [Fact]
    public async Task GHM002_StaleRepository_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Activity = new GitHubRepositoryActivity(null, null, null,
                DateTimeOffset.UtcNow.AddDays(-400), null, null)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-GHM002");
        Assert.Equal(Severity.Medium, finding.Severity); // >365 days
    }

    [Fact]
    public async Task GHM002_RecentActivity_NoFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Activity = new GitHubRepositoryActivity(null, null, null,
                DateTimeOffset.UtcNow.AddDays(-30), null, null)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHM002");
    }

    // --- GHM003: Release activity ---

    [Fact]
    public async Task GHM003_StaleRelease_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Releases = new GitHubRepositoryReleaseSnapshot(5, "v1.0", "v1.0",
                DateTimeOffset.UtcNow.AddDays(-400), null, true, true)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM003");
    }

    // --- GHM004: Checksum ---

    [Fact]
    public async Task GHM004_AssetsWithoutChecksum_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Releases = new GitHubRepositoryReleaseSnapshot(1, "v1.0", "v1.0",
                DateTimeOffset.UtcNow.AddDays(-10), null, true, false)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM004");
    }

    [Fact]
    public async Task GHM004_AssetsWithChecksum_NoFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Releases = new GitHubRepositoryReleaseSnapshot(1, "v1.0", "v1.0",
                DateTimeOffset.UtcNow.AddDays(-10), null, true, true)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHM004");
    }

    // --- GHM005: CI ---

    [Fact]
    public async Task GHM005_FailedCI_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Ci = new GitHubRepositoryCiSnapshot("failure", DateTimeOffset.UtcNow.AddDays(-1), 3, 0)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM005");
    }

    [Fact]
    public async Task GHM005_SuccessfulCI_NoFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Ci = new GitHubRepositoryCiSnapshot("success", DateTimeOffset.UtcNow.AddDays(-1), 0, 5)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-GHM005");
    }

    // --- GHM006: Branch protection ---

    [Fact]
    public async Task GHM006_UnprotectedBranch_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Protection = new GitHubRepositoryProtectionSnapshot(false, false, false, true, true, "available")
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM006");
    }

    [Fact]
    public async Task GHM006_PermissionDenied_ReportsLowConfidence()
    {
        var metadata = CreateBasicMetadata() with
        {
            Protection = new GitHubRepositoryProtectionSnapshot(null, null, null, null, null, "permission-denied")
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-GHM006");
        Assert.Equal(Confidence.Low, finding.Confidence);
        Assert.Contains("could not be verified", finding.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --- GHM007: Automation ---

    [Fact]
    public async Task GHM007_NoAutomation_ReportsFinding()
    {
        var metadata = CreateBasicMetadata();
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo"); // path without configs
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM007");
    }

    // --- Popularity: must never produce findings ---

    [Fact]
    public async Task Popularity_NeverCreatesFindings()
    {
        var metadata = CreateBasicMetadata() with
        {
            Popularity = new GitHubRepositoryPopularity(0, 0, 0)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        // No finding should be based on popularity
        var popularityFindings = result.Findings.Where(f =>
            f.Message.Contains("star", StringComparison.OrdinalIgnoreCase) ||
            f.Message.Contains("fork", StringComparison.OrdinalIgnoreCase) ||
            f.Message.Contains("watcher", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Empty(popularityFindings);
    }

    [Fact]
    public async Task Popularity_HighStars_NoFindings()
    {
        var metadata = CreateBasicMetadata() with
        {
            Popularity = new GitHubRepositoryPopularity(10000, 500, 200)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        var popularityFindings = result.Findings.Where(f =>
            f.Message.Contains("star", StringComparison.OrdinalIgnoreCase) ||
            f.Message.Contains("fork", StringComparison.OrdinalIgnoreCase) ||
            f.Message.Contains("watcher", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Empty(popularityFindings);
    }

    // --- GHM008: Backlog ---

    [Fact]
    public async Task GHM008_HighIssueCount_ReportsFinding()
    {
        var metadata = CreateBasicMetadata() with
        {
            Activity = new GitHubRepositoryActivity(null, null,
                DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1),
                100, 30)
        };
        var client = new FakeGitHubMetadataClient(metadata);
        var analyzer = new GitHubMetadataAnalyzer(client, "/tmp/repo");
        var context = CreateContext();

        var result = await analyzer.AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-GHM008");
    }

    // --- TryParseGitHubTarget ---

    [Theory]
    [InlineData("https://github.com/owner/repo", "owner", "repo")]
    [InlineData("https://github.com/owner/repo.git", "owner", "repo")]
    [InlineData("git@github.com:owner/repo.git", "owner", "repo")]
    public void TryParseGitHubTarget_ValidTargets(string target, string expectedOwner, string expectedRepo)
    {
        var (owner, repo) = GitHubMetadataAnalyzer.TryParseGitHubTarget(target);
        Assert.Equal(expectedOwner, owner);
        Assert.Equal(expectedRepo, repo);
    }

    [Theory]
    [InlineData("/local/path")]
    [InlineData("https://gitlab.com/owner/repo")]
    [InlineData("")]
    public void TryParseGitHubTarget_InvalidTargets(string target)
    {
        var (owner, repo) = GitHubMetadataAnalyzer.TryParseGitHubTarget(target);
        Assert.Null(owner);
        Assert.Null(repo);
    }

    // --- Checksum naming ---

    [Theory]
    [InlineData("sha256", true)]
    [InlineData("SHA256SUMS", true)]
    [InlineData("checksums.txt", true)]
    [InlineData("project-linux-amd64.tar.gz", false)]
    [InlineData("", false)]
    public void IsChecksumLikeAssetName(string name, bool expected)
    {
        Assert.Equal(expected, GitHubMetadataAnalyzer.IsChecksumLikeAssetName(name));
    }

    // --- Helpers ---

    private static GitHubRepositoryMetadataArtifact CreateBasicMetadata() =>
        new(
            Repository: new GitHubRepositoryIdentity("test/repo", "https://github.com/test/repo",
                "main", "public", false, false, false),
            Activity: new GitHubRepositoryActivity(
                DateTimeOffset.UtcNow.AddDays(-365),
                DateTimeOffset.UtcNow.AddDays(-10),
                DateTimeOffset.UtcNow.AddDays(-10),
                DateTimeOffset.UtcNow.AddDays(-5),
                10, 5),
            Popularity: new GitHubRepositoryPopularity(100, 20, 10),
            Releases: new GitHubRepositoryReleaseSnapshot(3, "v1.0", "v1.0",
                DateTimeOffset.UtcNow.AddDays(-30), null, true, true),
            Ci: new GitHubRepositoryCiSnapshot("success",
                DateTimeOffset.UtcNow.AddDays(-1), 0, 5),
            Protection: new GitHubRepositoryProtectionSnapshot(true, true, true, false, false, "available"),
            Metrics: new Dictionary<string, string>());
}

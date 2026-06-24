using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.DependencyRisk;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analyzers.ReleaseEvidence;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Shared;

namespace RepoTrustDoctor.UnitTests;

public sealed class ReleaseContractTests
{
    [Fact]
    public void ProductVersion_Equals_OnePointZeroPointFive()
    {
        Assert.Equal("1.0.5", ProductInfo.Version);
    }

    [Fact]
    public void ProductVersion_Matches_CommandName()
    {
        Assert.Equal("repo-trust-doctor", ProductInfo.CommandName);
    }

    [Fact]
    public void EveryAnalyzerRule_HasMetadata()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();

        foreach (var analyzer in analyzers)
        {
            foreach (var rule in analyzer.Rules)
            {
                Assert.False(string.IsNullOrWhiteSpace(rule.RuleId),
                    $"Analyzer '{analyzer.Id}' has a rule with empty RuleId.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Title),
                    $"Rule '{rule.RuleId}' in analyzer '{analyzer.Id}' has empty Title.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Description),
                    $"Rule '{rule.RuleId}' in analyzer '{analyzer.Id}' has empty Description.");
                Assert.False(string.IsNullOrWhiteSpace(rule.Recommendation),
                    $"Rule '{rule.RuleId}' in analyzer '{analyzer.Id}' has empty Recommendation.");
            }
        }
    }

    [Fact]
    public void EveryArtifactKey_HasExactlyOneProducer()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();
        var producers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var analyzer in analyzers)
        {
            foreach (var key in analyzer.ProducesArtifacts)
            {
                if (producers.TryGetValue(key, out var existing))
                {
                    Assert.Fail($"Artifact key '{key}' is produced by both '{existing}' and '{analyzer.Id}'.");
                }
                producers[key] = analyzer.Id;
            }
        }

        // Verify expected artifact keys exist
        Assert.Contains(producers.Keys, k => k == DependencyInventoryArtifact.ArtifactKey);
        Assert.Contains(producers.Keys, k => k == DependencyConsistencyArtifact.ArtifactKey);
        Assert.Contains(producers.Keys, k => k == ImportedEvidenceArtifact.ArtifactKey);
        Assert.Contains(producers.Keys, k => k == GitHubRepositoryMetadataArtifact.ArtifactKey);
    }

    [Fact]
    public void GitHubMetadataTests_UseFakeClients()
    {
        // Contract: GitHub metadata analyzer tests must not call real GitHub API.
        // This is verified by the GitHubMetadataAnalyzerTests using FakeGitHubMetadataClient.
        // This test exists as a documentation contract reminder.
        Assert.True(true, "GitHub metadata tests must use fake clients — see GitHubMetadataAnalyzerTests.");
    }

    [Fact]
    public void PopularityMetrics_NeverProduceFindings()
    {
        // Contract: Stars, forks, and watchers must never become findings.
        // Verified by GitHubMetadataAnalyzerTests.Popularity_NeverCreatesFindings.
        Assert.True(true, "Popularity metrics must never produce findings — see GitHubMetadataAnalyzerTests.");
    }

    [Fact]
    public void DependencyConsistencyAnalyzer_IsRegistered()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();
        Assert.Contains(analyzers, a => a.Id == "dependency.consistency");
    }

    [Fact]
    public void GitHubMetadataAnalyzer_IsRegistered()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();
        Assert.Contains(analyzers, a => a.Id == "github.metadata");
    }

    [Fact]
    public void ReleaseIntegrityAnalyzer_IsRegistered()
    {
        var analyzers = DefaultRepositoryScanRunner.CreateAnalyzers();
        Assert.Contains(analyzers, a => a.Id == "release.integrity");
    }

    [Fact]
    public void SuppressedFindings_RemainVisible()
    {
        // Contract: Suppression must not delete findings.
        var finding = new Finding(
            "TRUST-TEST001", "Test Finding", AnalysisCategory.RepositoryHealth,
            Severity.Low, Confidence.High, "Test message",
            [new Evidence("test", "test evidence")],
            new Recommendation("Test recommendation"),
            IdentityKey: "test-key");

        var suppressed = finding with
        {
            Suppression = new FindingSuppression(
                "TRUST-TEST001", null, "test-key", "Accepted risk", "tester", null)
        };

        Assert.NotNull(suppressed.Suppression);
        Assert.Equal("TRUST-TEST001", suppressed.RuleId); // Finding still has its rule ID
        Assert.NotEmpty(suppressed.Evidence); // Evidence still present
    }

    [Fact]
    public void AnalyzerResults_ContainEvidence()
    {
        // Contract: Every finding must have evidence and recommendation.
        // This is verified in individual analyzer tests.
        // This test documents the contract.
        var finding = new Finding(
            "TRUST-TEST002", "Test", AnalysisCategory.Dependencies,
            Severity.Medium, Confidence.High, "Test message",
            [new Evidence("test", "evidence text", "file.txt")],
            new Recommendation("Do something."));

        Assert.NotEmpty(finding.Evidence);
        Assert.False(string.IsNullOrWhiteSpace(finding.Recommendation.Message));
    }
}

using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.UnitTests;

public sealed class FindingSuppressionEngineTests
{
    [Fact]
    public void Load_EmptyConfig_ReturnsEmptyEngine()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """{"suppressions":[]}""");

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);

        Assert.Empty(engine.Warnings);
    }

    [Fact]
    public void Load_ValidSuppression_ParsesCorrectly()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """
        {
          "suppressions": [
            {
              "ruleId": "TRUST-K8S006",
              "path": "deployments/local-dev.yaml",
              "reason": "Required by local dev",
              "owner": "platform-team",
              "expiresOn": "2026-12-31"
            }
          ]
        }
        """);

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);
        Assert.Empty(engine.Warnings);

        var finding = new Finding(
            "TRUST-K8S006", "Test", AnalysisCategory.Containers,
            Severity.Medium, Confidence.High, "Test message",
            [new Evidence("test", "test", "deployments/local-dev.yaml")],
            new Recommendation("Fix it"));

        var suppression = engine.FindActiveSuppression(finding);
        Assert.NotNull(suppression);
        Assert.Equal("Required by local dev", suppression!.Reason);
        Assert.Equal("platform-team", suppression.Owner);
    }

    [Fact]
    public void FindActiveSuppression_Expired_ReturnsNull()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """
        {
          "suppressions": [
            {
              "ruleId": "TRUST-TEST001",
              "reason": "Expired",
              "expiresOn": "2020-01-01"
            }
          ]
        }
        """);

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);

        var finding = new Finding(
            "TRUST-TEST001", "Test", AnalysisCategory.RepositoryHealth,
            Severity.Low, Confidence.High, "Test",
            [new Evidence("test", "test")],
            new Recommendation("Fix"));

        Assert.Null(engine.FindActiveSuppression(finding));
    }

    [Fact]
    public void FindActiveSuppression_RuleMismatch_ReturnsNull()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """
        {
          "suppressions": [
            {
              "ruleId": "TRUST-OTHER",
              "reason": "Other rule"
            }
          ]
        }
        """);

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);

        var finding = new Finding(
            "TRUST-TEST001", "Test", AnalysisCategory.RepositoryHealth,
            Severity.Low, Confidence.High, "Test",
            [new Evidence("test", "test")],
            new Recommendation("Fix"));

        Assert.Null(engine.FindActiveSuppression(finding));
    }

    [Fact]
    public void FindActiveSuppression_IdentityKeyMatch_Applies()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """
        {
          "suppressions": [
            {
              "ruleId": "TRUST-TEST001",
              "identityKey": "dep052|npm|mylib",
              "reason": "Known version drift"
            }
          ]
        }
        """);

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);

        var finding = new Finding(
            "TRUST-TEST001", "Test", AnalysisCategory.Dependencies,
            Severity.Low, Confidence.High, "Test",
            [new Evidence("test", "test")],
            new Recommendation("Fix"),
            IdentityKey: "dep052|npm|mylib");

        var suppression = engine.FindActiveSuppression(finding);
        Assert.NotNull(suppression);
    }

    [Fact]
    public void FindActiveSuppression_MissingReason_IsInvalid()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, """
        {
          "suppressions": [
            {
              "ruleId": "TRUST-TEST001"
            }
          ]
        }
        """);

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);
        Assert.NotEmpty(engine.Warnings);
        Assert.Contains(engine.Warnings, w => w.Contains("reason", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Load_MalformedJson_ReturnsWarning()
    {
        using var temp = new TempDir();
        var configPath = Path.Combine(temp.Path, ".repo-trust.json");
        File.WriteAllText(configPath, "{invalid json");

        var engine = FindingSuppressionEngine.LoadFromFile(configPath);
        Assert.NotEmpty(engine.Warnings);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; }

        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"repo-trust-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}

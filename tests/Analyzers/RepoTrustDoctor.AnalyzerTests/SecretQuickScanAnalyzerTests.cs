using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class SecretQuickScanAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_RedactsSecretEvidenceAndReportsLineNumber()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        safe=true
        token={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET003");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(2, evidence.LineNumber);
        Assert.Equal("ghp_[redacted]", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsRedactedAwsAccessKey()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeKey = "AKIA" + "1234567890123456";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        aws_key={fakeKey}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET004");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Equal("AKIA[redacted]", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsRedactedConnectionString()
    {
        using var fixture = TemporaryRepository.Create();
        var connectionString = "Server=myServerAddress;" +
                               "User Id=myUsername;" +
                               "Password=myPassword;";

        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        {connectionString}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET005");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Equal(
            "Server=[redacted];" +
            "User Id=[redacted];" +
            "Password=[redacted]",
            evidence.Value);
    }


    [Fact]
    public async Task AnalyzeAsync_ReportsRedactedSlackWebhook()
    {
        using var fixture = TemporaryRepository.Create();
        var rawWebhook = "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        slack_url={rawWebhook}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET006");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Equal("https://hooks.slack.com/services/[redacted]", evidence.Value);
        Assert.DoesNotContain("T00000000", evidence.Value);
        Assert.DoesNotContain("B00000000", evidence.Value);
        Assert.DoesNotContain("XXXXXXXXXXXXXXXXXXXXXXXX", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsRedactedDiscordWebhook()
    {
        using var fixture = TemporaryRepository.Create();
        var rawWebhook1 = "https://discord.com/api/" + "webhooks/123456789/abcdef";
        var rawWebhook2 = "https://discordapp.com/api/" + "webhooks/987654321/fedcba";
        File.WriteAllText(Path.Combine(fixture.Path, "config1.txt"), $"""
        discord_url1={rawWebhook1}
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "config2.txt"), $"""
        discord_url2={rawWebhook2}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Equal(2, result.Findings.Count(finding => finding.RuleId == "TRUST-SECRET007"));

        var finding1 = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET007" && finding.Evidence[0].Value is string v1 && v1.Contains("https://discord.com"));
        var evidence1 = Assert.Single(finding1.Evidence);
        Assert.Equal("https://discord.com/api/webhooks/[redacted]", evidence1.Value);
        Assert.DoesNotContain("123456789", evidence1.Value ?? "");

        var finding2 = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET007" && finding.Evidence[0].Value is string v2 && v2.Contains("https://discordapp.com"));
        var evidence2 = Assert.Single(finding2.Evidence);
        Assert.Equal("https://discordapp.com/api/webhooks/[redacted]", evidence2.Value);
        Assert.DoesNotContain("987654321", evidence2.Value ?? "");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportNormalUrl()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        normal_url=https://github.com/owner/repo
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_SkipsSecretFindings_InExampleFixturePaths()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";

        // Create a directory matching fixture path
        Directory.CreateDirectory(Path.Combine(fixture.Path, "tests", "Fixtures"));
        File.WriteAllText(Path.Combine(fixture.Path, "tests", "Fixtures", "sample.txt"), $"""
        token={fakeToken}
        """);

        // Create a normal directory path
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src"));
        File.WriteAllText(Path.Combine(fixture.Path, "src", "sample.txt"), $"""
        token={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        // Should report exactly one token finding, which is in the src directory, and none in tests/Fixtures/
        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET003");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Contains("src/sample.txt", evidence.FilePath?.Replace('\\', '/'));
    }

    [Fact]
    public async Task AnalyzeAsync_SkipsBinaryFilesWithNullBytes()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        var tokenBytes = System.Text.Encoding.UTF8.GetBytes($"token={fakeToken}\n");
        var content = new byte[tokenBytes.Length + 4];
        Array.Copy(tokenBytes, content, tokenBytes.Length);
        content[tokenBytes.Length] = 0; // Null byte sniffer check

        File.WriteAllBytes(Path.Combine(fixture.Path, "binary.bin"), content);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_ReadsNormalUtf8TextFile()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        File.WriteAllText(Path.Combine(fixture.Path, "text.txt"), $"""
        token={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET003");
    }

    [Fact]
    public async Task AnalyzeAsync_HandlesDeletedOrUnreadableFilesGracefully()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        var filePath = Path.Combine(fixture.Path, "deleted.txt");
        File.WriteAllText(filePath, $"""
        token={fakeToken}
        """);

        File.Delete(filePath);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsAzureConnectionString()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeConnectionString = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz==";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        azure_cs={fakeConnectionString}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET008");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Contains("[redacted]", evidence.Value);
        Assert.DoesNotContain("AccountKey", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsGcpServiceAccountKey()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "sa.json"), """
        {
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "abc123"
        }
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET009");
        Assert.True(finding.IsBlocking);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal("sa.json", evidence.FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsJwtToken()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        token={fakeJwt}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET010");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Contains("[redacted]", evidence.Value);
        Assert.DoesNotContain("eyJ", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsNpmToken()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeNpmToken = "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789";
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), $"""
        //registry.npmjs.org/:_authToken={fakeNpmToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET011");
        var evidence = Assert.Single(finding.Evidence);
        Assert.Equal(1, evidence.LineNumber);
        Assert.Contains("[redacted]", evidence.Value);
        Assert.DoesNotContain("npm_", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsPyPIToken()
    {
        using var fixture = TemporaryRepository.Create();
        var fakePypiToken = "pypi-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
        File.WriteAllText(Path.Combine(fixture.Path, ".pypirc"), $"""
        password={fakePypiToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET011");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsGenericApiKey()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_key=sk-abcdefghijklmnopqrstuvwxyz123456
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET012");
        Assert.Equal(Confidence.Low, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Contains("[redacted]", evidence.Value);
        Assert.DoesNotContain("sk-", evidence.Value);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsGitCredentialsFile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".git-credentials"), "https://user:pass@example.com");

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET001");
        Assert.Contains(".git-credentials", finding.Evidence[0].FilePath, StringComparison.Ordinal);
    }
}



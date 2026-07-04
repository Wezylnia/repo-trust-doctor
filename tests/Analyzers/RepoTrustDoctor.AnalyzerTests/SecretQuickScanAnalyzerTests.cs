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

    [Theory]
    [InlineData("Password=secret123;Server=db;User Id=admin;")]
    [InlineData("User Id=admin;Password=secret123;Host=db;")]
    [InlineData("Data Source=db;Pwd=secret123;")]
    public async Task AnalyzeAsync_ReportsConnectionStringRegardlessOfFieldOrder(string connectionString)
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), connectionString);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-SECRET005");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportConnectionStringWithPlaceholderPassword()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        Password=changeme;Server=db;User Id=admin;
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET005");
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
    public async Task AnalyzeAsync_SkipsSecretFindings_InVendoredPaths()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";

        Directory.CreateDirectory(Path.Combine(fixture.Path, "vendor", "pkg"));
        File.WriteAllText(Path.Combine(fixture.Path, "vendor", "pkg", "config.txt"), $"""
        token={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET003");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsSensitiveFileNames_InExampleFixturePaths()
    {
        using var fixture = TemporaryRepository.Create();

        Directory.CreateDirectory(Path.Combine(fixture.Path, "tests", "Fixtures"));
        File.WriteAllText(Path.Combine(fixture.Path, "tests", "Fixtures", ".env"), """
        API_KEY=example
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs", "examples"));
        File.WriteAllText(Path.Combine(fixture.Path, "docs", "examples", ".env.production"), """
        API_KEY=example
        """);

        File.WriteAllText(Path.Combine(fixture.Path, ".env"), """
        API_KEY=real-looking
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var sensitivePaths = result.Findings
            .Where(f => f.RuleId == "TRUST-SECRET001")
            .Select(f => Assert.Single(f.Evidence).FilePath)
            .ToArray();

        Assert.Contains(".env", sensitivePaths);
        Assert.Contains("tests/Fixtures/.env", sensitivePaths);
        Assert.Contains("docs/examples/.env.production", sensitivePaths);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsRealTokenInsideTestEnvFile()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";

        Directory.CreateDirectory(Path.Combine(fixture.Path, "tests", "Fixtures"));
        File.WriteAllText(Path.Combine(fixture.Path, "tests", "Fixtures", ".env"), $"""
        GITHUB_TOKEN={fakeToken}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET001" && f.Evidence[0].FilePath == "tests/Fixtures/.env");
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET003" && f.Evidence[0].FilePath == "tests/Fixtures/.env");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsRealPrivateKeyInsideFixtureSensitiveFile()
    {
        using var fixture = TemporaryRepository.Create();

        Directory.CreateDirectory(Path.Combine(fixture.Path, "fixtures", "auth"));
        File.WriteAllText(Path.Combine(fixture.Path, "fixtures", "auth", "id_rsa"), """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbE2m7LlJx4c7y
        -----END PRIVATE KEY-----
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET001" && f.Evidence[0].FilePath == "fixtures/auth/id_rsa");
        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET002" && f.Evidence[0].FilePath == "fixtures/auth/id_rsa");
    }

    [Fact]
    public async Task AnalyzeAsync_SkipsSensitiveFiles_InCommonTestAndPlaygroundPaths()
    {
        using var fixture = TemporaryRepository.Create();

        Directory.CreateDirectory(Path.Combine(fixture.Path, "tests", "TestFiles", "ClientCertificates"));
        File.WriteAllText(Path.Combine(fixture.Path, "tests", "TestFiles", "ClientCertificates", "client.key"), """
        test key fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "packages", "app", "__tests__", "fixtures", "env"));
        File.WriteAllText(Path.Combine(fixture.Path, "packages", "app", "__tests__", "fixtures", "env", ".env"), """
        API_KEY=example
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "playground", "env"));
        File.WriteAllText(Path.Combine(fixture.Path, "playground", "env", ".env.production"), """
        API_KEY=example
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "core", "spring-boot", "src", "test", "resources", "ssl"));
        File.WriteAllText(Path.Combine(fixture.Path, "core", "spring-boot", "src", "test", "resources", "ssl", "rsa-key.pem"), """
        test key fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "src", "Shared", "TestCertificates"));
        File.WriteAllText(Path.Combine(fixture.Path, "src", "Shared", "TestCertificates", "https.key"), """
        test certificate fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "src", "DefaultBuilder", "samples", "SampleApp"));
        File.WriteAllText(Path.Combine(fixture.Path, "src", "DefaultBuilder", "samples", "SampleApp", "cert.pfx"), """
        sample certificate fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "cmd", "kube-apiserver", "app", "testing"));
        File.WriteAllText(Path.Combine(fixture.Path, "cmd", "kube-apiserver", "app", "testing", "testserver.go"), """
        const key = "-----BEGIN PRIVATE KEY-----"
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "module", "spring-boot-amqp", "src", "dockerTest", "resources"));
        File.WriteAllText(Path.Combine(fixture.Path, "module", "spring-boot-amqp", "src", "dockerTest", "resources", "client.key"), """
        docker test certificate fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "integration-test", "app", "src", "main", "resources"));
        File.WriteAllText(Path.Combine(fixture.Path, "integration-test", "app", "src", "main", "resources", "server.key"), """
        integration test certificate fixture
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "test", "integration", "auth"));
        File.WriteAllText(Path.Combine(fixture.Path, "test", "integration", "auth", "svcaccttoken_test.go"), """
        const key = "-----BEGIN PRIVATE KEY-----"
        """);

        Directory.CreateDirectory(Path.Combine(fixture.Path, "documentation", "how-to"));
        File.WriteAllText(Path.Combine(fixture.Path, "documentation", "how-to", "webserver.adoc"), """
        -----
        -----BEGIN PRIVATE KEY-----
        documentation example
        -----
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding =>
            finding.RuleId == "TRUST-SECRET002");
        Assert.DoesNotContain(result.Findings, finding =>
            finding.RuleId == "TRUST-SECRET001" &&
            finding.Evidence.FirstOrDefault()?.FilePath is not "packages/app/__tests__/fixtures/env/.env" and
                not "playground/env/.env.production");
    }

    [Fact]
    public async Task AnalyzeAsync_SkipsSensitiveFiles_InRestTestAndDocumentationPaths()
    {
        using var fixture = TemporaryRepository.Create();

        var javaRestKey = Path.Combine(fixture.Path, "modules", "data-streams", "src", "javaRestTest", "resources", "ssl", "ca.key");
        Directory.CreateDirectory(Path.GetDirectoryName(javaRestKey)!);
        File.WriteAllText(javaRestKey, "java REST test certificate fixture");

        var yamlRestKey = Path.Combine(fixture.Path, "x-pack", "qa", "reindex-tests-with-security", "src", "yamlRestTest", "resources", "ssl", "http.key");
        Directory.CreateDirectory(Path.GetDirectoryName(yamlRestKey)!);
        File.WriteAllText(yamlRestKey, "YAML REST test certificate fixture");

        var docsCert = Path.Combine(fixture.Path, "docs", "httpCa.p12");
        Directory.CreateDirectory(Path.GetDirectoryName(docsCert)!);
        File.WriteAllText(docsCert, "documentation certificate fixture");

        File.WriteAllText(Path.Combine(fixture.Path, "prod.key"), "production key material");

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET001");
        Assert.Equal("prod.key", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_PublicCertificatePem_DoesNotReportSensitiveFile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "public-ca.pem"), """
        -----BEGIN CERTIFICATE-----
        MIIDpubliccertificate
        -----END CERTIFICATE-----
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "private-ca.key"), "private key material");

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET001");
        Assert.Equal("private-ca.key", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_SourceCodePrivateKeyMarkerWithoutBlock_DoesNotReportSecret002()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src"));
        File.WriteAllText(Path.Combine(fixture.Path, "src", "keyMarkers.ts"), """
        export const privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        export const privateKeyBlockPattern = /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g;
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "secrets.txt"), """
        -----BEGIN PRIVATE KEY-----
        abcdefghijklmnopqrstuvwxyz
        -----END PRIVATE KEY-----
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET002");
        Assert.Equal("secrets.txt", Assert.Single(finding.Evidence).FilePath);
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
    public async Task AnalyzeAsync_BudgetsSourceFilesButKeepsConfigurationCoverage()
    {
        using var fixture = TemporaryRepository.Create();
        var sourceToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";
        var configToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz654321";
        Directory.CreateDirectory(Path.Combine(fixture.Path, "src"));
        File.WriteAllText(Path.Combine(fixture.Path, "settings.json"), $$"""
        { "token": "{{configToken}}" }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "src", "a.cs"), """
        public sealed class A { }
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "src", "b.cs"), $$"""
        public sealed class B { private const string Token = "{{sourceToken}}"; }
        """);

        var analyzer = new SecretQuickScanAnalyzer(maxSourceContentScanFiles: 1);
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-SECRET003");
        Assert.Equal("settings.json", Assert.Single(finding.Evidence).FilePath);
        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("skipped 1 lower-priority source files", StringComparison.Ordinal));
        Assert.NotNull(result.Metrics);
        Assert.Equal("1", result.Metrics["secret.source.content.scanned.count"]);
        Assert.Equal("1", result.Metrics["secret.source.content.skipped.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_DefaultSourceBudgetBoundsBroadSourceScanning()
    {
        using var fixture = TemporaryRepository.Create();
        var sourceDirectory = Path.Combine(fixture.Path, "src");
        Directory.CreateDirectory(sourceDirectory);

        for (var index = 0; index < 801; index++)
        {
            File.WriteAllText(
                Path.Combine(sourceDirectory, $"file{index:D3}.cs"),
                "public sealed class Sample { public string Value => \"safe\"; }");
        }

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Empty(result.Findings);
        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("skipped 1 lower-priority source files", StringComparison.Ordinal));
        Assert.NotNull(result.Metrics);
        Assert.Equal("800", result.Metrics["secret.source.content.scanned.count"]);
        Assert.Equal("1", result.Metrics["secret.source.content.skipped.count"]);
    }

    [Fact]
    public async Task AnalyzeAsync_DeepScanExpandsSourceCoverageBeyondFastBudget()
    {
        using var fixture = TemporaryRepository.Create();
        var sourceDirectory = Path.Combine(fixture.Path, "src");
        Directory.CreateDirectory(sourceDirectory);
        var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456";

        for (var index = 0; index < 801; index++)
        {
            var content = index == 800
                ? $"public static class Last {{ private const string Token = \"{fakeToken}\"; }}"
                : "public sealed class Sample { public string Value => \"safe\"; }";
            File.WriteAllText(Path.Combine(sourceDirectory, $"file{index:D3}.cs"), content);
        }

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep),
            CancellationToken.None);

        var finding = Assert.Single(result.Findings, item => item.RuleId == "TRUST-SECRET003");
        Assert.Equal("src/file800.cs", Assert.Single(finding.Evidence).FilePath);
        Assert.Equal("801", result.Metrics!["secret.source.content.scanned.count"]);
        Assert.Equal("0", result.Metrics["secret.source.content.skipped.count"]);
        Assert.Equal("100", result.Metrics["secret.source.content.coverage.percent"]);
    }

    [Fact]
    public async Task AnalyzeAsync_BudgetsConfigurationFilesButKeepsCredentialConfigs()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeNpmToken = "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789";
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), $"""
        //registry.npmjs.org/:_authToken={fakeNpmToken}
        """);
        File.WriteAllText(Path.Combine(fixture.Path, "appsettings.json"), """
        { "api_key": "Abcdefghijklmnop1234567890" }
        """);

        var analyzer = new SecretQuickScanAnalyzer(maxSourceContentScanFiles: 100, maxConfigurationContentScanFiles: 0);
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-SECRET011");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET012");
        Assert.NotNull(result.Warnings);
        Assert.Contains(result.Warnings, warning => warning.Contains("skipped 1 lower-priority configuration files", StringComparison.Ordinal));
        Assert.NotNull(result.Metrics);
        Assert.Equal("0", result.Metrics["secret.configuration.content.scanned.count"]);
        Assert.Equal("1", result.Metrics["secret.configuration.content.skipped.count"]);
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
        var serviceAccountType = "service_" + "account";
        File.WriteAllText(Path.Combine(fixture.Path, "sa.json"), $$"""
        {
            "type": "{{serviceAccountType}}",
            "project_id": "my-project",
            "private_key_id": "abc123",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDsample\n-----END PRIVATE KEY-----\n",
            "client_email": "scanner@my-project.iam.gserviceaccount.com"
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
    public async Task AnalyzeAsync_ServiceAccountTypeWithoutPrivateKey_NoGcpFinding()
    {
        using var fixture = TemporaryRepository.Create();
        var serviceAccountType = "service_" + "account";
        File.WriteAllText(Path.Combine(fixture.Path, "sa.json"), $$"""
        {
            "type": "{{serviceAccountType}}",
            "project_id": "my-project",
            "private_key_id": "abc123"
        }
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET009");
    }

    [Fact]
    public async Task AnalyzeAsync_DocumentationPrivateKeyWithRealMaterial_ReportsSecret002()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs", "operations"));
        File.WriteAllText(Path.Combine(fixture.Path, "docs", "operations", "incident.md"), """
        # Incident note

        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbE2m7LlJx4c7y
        -----END PRIVATE KEY-----
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET002");
        Assert.Equal("docs/operations/incident.md", Assert.Single(finding.Evidence).FilePath);
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsJwtToken()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeJwt = string.Join(
            ".",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
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
    public async Task AnalyzeAsync_DoesNotReportJwtToken_InMarkdownDocumentation()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeJwt = string.Join(
            ".",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs", "tutorial"));
        File.WriteAllText(Path.Combine(fixture.Path, "docs", "tutorial", "oauth2.md"), $"""
        Example token:
        {fakeJwt}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET010");
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
    public async Task AnalyzeAsync_NpmrcWithoutToken_DoesNotReportSensitiveFile()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, ".npmrc"), """
        legacy-peer-deps=true
        registry=https://registry.npmjs.org/
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET001");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET011");
    }

    [Fact]
    public async Task AnalyzeAsync_PypiRegistryCallSite_DoesNotReportRegistryToken()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "commands.ts"), """
        const response = await fetch(url, { method: 'GET', callSite: 'mcp-pypi-registry' });
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-SECRET011");
    }

    [Fact]
    public async Task AnalyzeAsync_ReportsGenericApiKey()
    {
        using var fixture = TemporaryRepository.Create();
        var fakeApiKey = "Abcdefghijk" + "1234567890XYZ";
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), $"""
        api_key={fakeApiKey}
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        var finding = Assert.Single(result.Findings, f => f.RuleId == "TRUST-SECRET012");
        Assert.Equal(Confidence.Low, finding.Confidence);
        var evidence = Assert.Single(finding.Evidence);
        Assert.Contains("[redacted]", evidence.Value);
        Assert.DoesNotContain("api_key", evidence.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportGenericApiKey_ForPlaceholderValues()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_key=your-api-key-here-12345
        api_secret=changeme1234567890
        apikey=placeholder-abcdefghij
        api_key=test-token
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_DocumentationPlaceholderSecrets_DoNotProduceContentFindings()
    {
        using var fixture = TemporaryRepository.Create();
        Directory.CreateDirectory(Path.Combine(fixture.Path, "docs", "examples"));
        File.WriteAllText(Path.Combine(fixture.Path, "docs", "examples", "configuration.md"), """
        # Example configuration

        ```text
        GITHUB_TOKEN=ghp_placeholderplaceholderplaceholder123
        AWS_ACCESS_KEY_ID=AKIA0000000000000000
        Server=localhost;User Id=example;Password=changeme;
        api_key=your-api-key-here-12345
        ```
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId is "TRUST-SECRET003" or "TRUST-SECRET004" or "TRUST-SECRET005" or "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_GenericApiKeyPlaceholderCheckDoesNotSuppressEmbeddedTestSubstring()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_key=AbcdefTest1234567890XYZ
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_GenericApiKeyStrengthUsesOnlyAssignedValue()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_secret=Abcdefghij123456789
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_GenericApiKeyReportsTwentyCharacterStrongValue()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_secret=Abcdefghij1234567890
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.Contains(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportGenericApiKey_ForVariableReferences()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_key=${API_KEY}
        secret=${{ secrets.API_KEY }}
        token=%MY_TOKEN%
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotReportGenericApiKey_ForAllLowercaseDigits()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "config.txt"), """
        api_key=abcdefghijklmnop1234567890
        """);

        var analyzer = new SecretQuickScanAnalyzer();
        var result = await analyzer.AnalyzeAsync(new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Fast), CancellationToken.None);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == "TRUST-SECRET012");
    }
}



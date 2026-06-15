using RepoTrustDoctor.Analyzers.PackageRegistryConfig;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class PackageRegistryConfigAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_DetectsHttpRegistry()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "registry=http://example.com\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-REG001");
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotDuplicateNuGetConfigFindings()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(f.Path, "NuGet.config"),
            "<configuration><packageSources><add key=\"feed\" value=\"http://example.com/v3/index.json\" /></packageSources></configuration>");

        var result = await new PackageRegistryConfigAnalyzer().AnalyzeAsync(
            new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-REG001");
    }

    [Theory]
    [InlineData("http://localhost:4873")]
    [InlineData("http://127.0.0.1:4873")]
    [InlineData("http://[::1]:4873")]
    public async Task AnalyzeAsync_LoopbackHttp_NoREG001(string registryUrl)
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), $"registry={registryUrl}\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-REG001");
    }

    [Theory]
    [InlineData("http://notlocalhost.example")]
    [InlineData("http://127.0.0.1.example")]
    [InlineData("http://registry.example/localhost")]
    public async Task AnalyzeAsync_LoopbackTextInRemoteUrl_ReportsREG001(string registryUrl)
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), $"registry={registryUrl}\n");

        var analyzer = new PackageRegistryConfigAnalyzer();
        var result = await analyzer.AnalyzeAsync(
            new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REG001");
    }

    [Fact]
    public async Task AnalyzeAsync_CommentedHttpRegistry_NoREG001()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "# registry=http://example.com\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-REG001");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsGlobalAlwaysAuth()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "always-auth=true\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-REG002");
    }

    [Fact]
    public async Task AnalyzeAsync_GlobalAlwaysAuthWithScopedToken_StillReportsREG002()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(f.Path, ".npmrc"),
            """
            always-auth=true
            //registry.npmjs.org/:_authToken=${NPM_TOKEN}
            """);

        var result = await new PackageRegistryConfigAnalyzer().AnalyzeAsync(
            new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-REG002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-REG003");
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsInlineToken()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "_authToken=secret123\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-REG003" && x.Category == AnalysisCategory.Dependencies);
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsScopedNpmTokenLine()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "//registry.npmjs.org/:_authToken=secret123\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(r.Findings, x => x.RuleId == "TRUST-REG003");
        Assert.DoesNotContain("secret123", finding.Evidence[0].Message);
    }

    [Fact]
    public async Task AnalyzeAsync_EnvVarToken_NoREG003()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "_authToken=${NPM_TOKEN}\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-REG003");
    }

    [Theory]
    [InlineData("https://repo.tools.internal", false)]
    [InlineData("http://localhost:8081", false)]
    [InlineData("https://public.example/path/.internal", true)]
    [InlineData("https://notinternal.example", true)]
    public async Task AnalyzeAsync_MavenMirrorAll_UsesParsedHost(
        string mirrorUrl,
        bool expectFinding)
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, "settings.xml"), $$"""
            <settings>
              <mirrors>
                <mirror>
                  <id>all</id>
                  <mirrorOf>*</mirrorOf>
                  <url>{{mirrorUrl}}</url>
                </mirror>
              </mirrors>
            </settings>
            """);

        var result = await new PackageRegistryConfigAnalyzer().AnalyzeAsync(
            new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        Assert.Equal(
            expectFinding,
            result.Findings.Any(finding => finding.RuleId == "TRUST-REG004"));
    }

    [Fact]
    public async Task AnalyzeAsync_DetectsInsecureProtocol()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, "settings.gradle"), "allowInsecureProtocol = true\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-REG005");
    }

    [Fact]
    public async Task AnalyzeAsync_InsecureProtocolFalse_NoREG005()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, "settings.gradle"), "allowInsecureProtocol = false\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-REG005");
    }

    [Fact]
    public async Task AnalyzeAsync_RedactsCredentialsFromRegistryUrlEvidence()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "registry=http://user:pass@example.com/npm?token=secret\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);

        var finding = Assert.Single(r.Findings, x => x.RuleId == "TRUST-REG001");
        var evidence = finding.Evidence[0].Message;
        Assert.Contains("http://example.com/npm", evidence);
        Assert.DoesNotContain("user", evidence);
        Assert.DoesNotContain("pass", evidence);
        Assert.DoesNotContain("token=secret", evidence);
    }

    [Fact]
    public async Task AnalyzeAsync_DoesNotExposeMalformedRegistryCredentials()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(
            Path.Combine(f.Path, ".npmrc"),
            "registry=http://user:supersecret@\n");

        var result = await new PackageRegistryConfigAnalyzer().AnalyzeAsync(
            new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard),
            CancellationToken.None);

        var finding = Assert.Single(
            result.Findings,
            finding => finding.RuleId == "TRUST-REG001");
        Assert.Contains("unparseable-registry-url", finding.Evidence[0].Message);
        Assert.DoesNotContain("user", finding.Evidence[0].Message);
        Assert.DoesNotContain("supersecret", finding.Evidence[0].Message);
    }
}

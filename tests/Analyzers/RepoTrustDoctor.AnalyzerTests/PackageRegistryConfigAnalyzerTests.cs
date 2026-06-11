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
    public async Task AnalyzeAsync_LocalhostHttp_NoREG001()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "registry=http://localhost:4873\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == "TRUST-REG001");
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
    public async Task AnalyzeAsync_DetectsInlineToken()
    {
        using var f = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(f.Path, ".npmrc"), "_authToken=secret123\n");

        var a = new PackageRegistryConfigAnalyzer();
        var r = await a.AnalyzeAsync(new AnalysisContext(f.Path, f.Path, AnalysisDepth.Standard), CancellationToken.None);
        Assert.Contains(r.Findings, x => x.RuleId == "TRUST-REG003");
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
}

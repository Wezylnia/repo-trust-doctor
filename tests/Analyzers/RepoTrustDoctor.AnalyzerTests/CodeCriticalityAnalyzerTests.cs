using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class CodeCriticalityAnalyzerTests
{
    [Fact]
    public async Task CodeCriticalityAnalyzer_DetectsSecuritySensitiveFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "auth");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "TokenService.cs"), """
        public sealed class TokenService
        {
            public string CreateJwt(string password, string secret)
            {
                return Authenticate(password) + secret;
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE004");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Contains(CodeCriticalityReason.Authentication, file.Reasons);
        Assert.Contains(CodeCriticalityReason.Secrets, file.Reasons);
        Assert.True(file.Score >= 50);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DetectsLargeCriticalFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "payments");
        Directory.CreateDirectory(directory);
        var lines = Enumerable.Repeat("public void ChargeCard() { paymentGateway.Authorize(); }", 405);
        File.WriteAllText(Path.Combine(directory, "PaymentProcessor.cs"), string.Join(Environment.NewLine, lines));
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE005");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Contains(CodeCriticalityReason.LargeFile, Assert.Single(artifact.Files).Reasons);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DetectsBroadExceptionHandlingInCriticalFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "data");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "UserRepository.cs"), """
        public sealed class UserRepository
        {
            public void SavePassword(string password)
            {
                try { database.Save(password); }
                catch (Exception) { }
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE006");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Contains(CodeCriticalityReason.BroadExceptionHandling, Assert.Single(artifact.Files).Reasons);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_IgnoresNonCriticalSmallFiles()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "README.md"), "payment token secret");
        File.WriteAllText(Path.Combine(fixture.Path, "src.cs"), "public sealed class Greeting { public string Say() => \"hello\"; }");
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DetectsDeserializationAndCommandExecution()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "unsafe");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "UnsafeHandler.cs"), """
        public sealed class UnsafeHandler
        {
            public void ProcessInput(byte[] payload)
            {
                var formatter = new BinaryFormatter();
                var obj = formatter.Deserialize(new MemoryStream(payload));
                System.Diagnostics.Process.Start("cmd.exe", "/c " + obj.ToString());
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE014");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Contains(CodeCriticalityReason.Deserialization, file.Reasons);
        Assert.Contains(CodeCriticalityReason.CommandExecution, file.Reasons);
    }
}

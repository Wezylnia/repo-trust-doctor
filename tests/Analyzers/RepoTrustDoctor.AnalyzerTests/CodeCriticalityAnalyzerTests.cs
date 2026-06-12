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
    public async Task CodeCriticalityAnalyzer_DoesNotReportFilteredExceptionHandlingAsBroad()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "reports");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "CoverageReader.cs"), """
        public sealed class CoverageReader
        {
            public void ReadPasswordReport(string password)
            {
                try { File.ReadAllText(password); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE006");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(Assert.Single(artifact.Files).Reasons, reason => reason == CodeCriticalityReason.BroadExceptionHandling);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportDiagnosticBoundaryExceptionHandlersAsBroad()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "workers");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "ScanWorker.cs"), """
        public sealed class ScanWorker
        {
            public void Run(string secret)
            {
                try { File.ReadAllText(secret); }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Worker failed.");
                    State = ScanLifecycleState.Failed;
                }
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE006");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(Assert.Single(artifact.Files).Reasons, reason => reason == CodeCriticalityReason.BroadExceptionHandling);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotTreatInfrastructureTypeNamesAsSecretOrCryptoSignals()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "jobs");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "BackgroundJob.cs"), """
        public sealed class BackgroundJob
        {
            public Task RunAsync(CancellationToken cancellationToken)
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                return Task.CompletedTask;
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotTreatAnalyzerVocabularyAsApplicationCriticality()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "contracts");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "CodebaseArtifacts.cs"), """
        public enum CodeCriticalityReason
        {
            Authentication,
            Authorization,
            Payments,
            Database,
            FileSystem,
            Network,
            Cryptography,
            Secrets
        }

        public sealed class RuleMapper
        {
            public string Map(CodeCriticalityReason reason) => CodeCriticalityReason.Authentication.ToString();
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportStaticAnalyzerRuleVocabularyAsApplicationCriticality()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "Analyzers", "CiCd");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "WorkflowSecurityAnalyzer.cs"), """
        using System.Text.RegularExpressions;

        public sealed partial class WorkflowSecurityAnalyzer : IRepositoryAnalyzer
        {
            public async Task AnalyzeAsync(string path)
            {
                var content = await File.ReadAllTextAsync(path);
                if (PermissionsPattern().IsMatch(content))
                {
                    CheckHardcodedSecretsInEnv(content);
                }
            }

            private static void CheckHardcodedSecretsInEnv(string content) { }

            [GeneratedRegex("permissions:|secrets\\.")]
            private static partial Regex PermissionsPattern();
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE004");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_StillReportsCommandExecutionInsideStaticAnalyzerImplementations()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "Analyzers", "Dangerous");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "DangerousAnalyzer.cs"), """
        public sealed class DangerousAnalyzer : IRepositoryAnalyzer
        {
            public void Analyze(string command)
            {
                System.Diagnostics.Process.Start("cmd.exe", command);
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Contains(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution));
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
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Contains(CodeCriticalityReason.Deserialization, file.Reasons);
        Assert.Contains(CodeCriticalityReason.CommandExecution, file.Reasons);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DetectsCommandExecutionWithoutOtherSignals()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "jobs");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "CommandRunner.cs"), """
        public sealed class CommandRunner
        {
            public void Run()
            {
                System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Contains(CodeCriticalityReason.CommandExecution, file.Reasons);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportBoundedProcessStartInfoAsCommandExecution()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "git");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "GitRunner.cs"), """
        using System.Diagnostics;

        public sealed class GitRunner
        {
            public void Run(string repositoryUrl, string clonePath)
            {
                using var process = new Process();
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    UseShellExecute = false
                };
                process.StartInfo.ArgumentList.Add("clone");
                process.StartInfo.ArgumentList.Add(repositoryUrl);
                process.StartInfo.ArgumentList.Add(clonePath);
                process.Start();
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution));
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_IgnoresDangerousTermsInsideStringLiterals()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "docs");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "RuleText.cs"), """
        public sealed class RuleText
        {
            public string Message => "BinaryFormatter and Process.Start are examples in documentation only.";
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-CODE014" or "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_IgnoresDangerousTermsInsideComments()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "docs");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "CommentOnly.cs"), """
        public sealed class CommentOnly
        {
            // Process.Start, BinaryFormatter, password, secret, and token are mentioned in a comment.
            /* authorization, payment, database, network, and crypto are also documentation notes. */
            public string Say() => "hello";
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_SkipsTestSourceFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "tests");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "UnsafeHandlerTests.cs"), """
        public sealed class UnsafeHandlerTests
        {
            public void Fixture()
            {
                System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }
}

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
    public async Task CodeCriticalityAnalyzer_DoesNotReportWrappedRethrowAsBroad()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "auth");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "BeanFactory.java"), """
        public final class BeanFactory {
            public Object authenticate(String password) {
                try {
                    return createBean(password);
                }
                catch (Throwable ex) {
                    throw new BeanCreationException("Authentication bean failed", ex);
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
    public async Task CodeCriticalityAnalyzer_DoesNotReportPythonLoggerExceptionAsBroad()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "auth");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "password_reset.py"), """
        def send_password_reset_email(password):
            try:
                authenticate(password)
                mailer.send(password)
            except Exception:
                logger.exception("Failed to send password reset email")
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE006");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(Assert.Single(artifact.Files).Reasons, reason => reason == CodeCriticalityReason.BroadExceptionHandling);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportExplicitModuleFailureAsBroad()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "modules");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "git.py"), """
        def read_token_file(path, module):
            try:
                with open(path) as handle:
                    access_token = handle.read()
                    database.save(access_token)
                    return access_token
            except Exception:
                module.fail_json(msg="Unable to read access_token file")
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
    public async Task CodeCriticalityAnalyzer_ReportsToolingCommandExecutionAsMediumSeverity()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "build", "scripts");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "build.py"), """
        import subprocess

        def run_build(target):
            subprocess.run(["ninja", target], check=True)
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Command execution in build or tooling code", finding.Title);
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
    public async Task CodeCriticalityAnalyzer_DoesNotTreatJavaSerializationImportsAsDeserializationUsage()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "java");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "SerializableType.java"), """
        package sample;

        import java.io.ObjectInputStream;
        import java.io.Serializable;

        public final class SerializableType implements Serializable {
            private String value;
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE014");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE017");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.Deserialization));
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.JavaSerializationHook));
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_ReportsJavaReadObjectAsSerializationHookAtUsageLine()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "java");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "SerializableType.java"), """
        package sample;

        import java.io.IOException;
        import java.io.ObjectInputStream;
        import java.io.Serializable;

        public final class SerializableType implements Serializable {
            private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
                value = (String) input.readObject();
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE014");
        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-CODE017");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(8, Assert.Single(finding.Evidence).LineNumber);
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Equal(8, file.RelevantLines![CodeCriticalityReason.JavaSerializationHook]);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotDuplicateJavaSerializationHookWhenUnsafeDeserializationIsReported()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "java");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "UnsafeDeserializer.java"), """
        package sample;

        import java.io.InputStream;
        import java.io.ObjectInputStream;

        public final class UnsafeDeserializer {
            Object deserialize(InputStream input) throws Exception {
                return new ObjectInputStream(input).readObject();
            }
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE014");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE017");
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
    public async Task CodeCriticalityAnalyzer_DoesNotTreatSubprocessImportAsCommandExecution()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "tools");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "helper.py"), """
        import subprocess

        def describe():
            return "helper"
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.CommandExecution));
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_ReportsSubprocessInvocationAtCallLine()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "tools");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "runner.py"), """
        import subprocess

        def run(args):
            return subprocess.Popen(args)
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        Assert.Equal(4, Assert.Single(finding.Evidence).LineNumber);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_ReportsPythonSubprocessWithoutShellAsBoundedMediumRisk()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "database");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "client.py"), """
        import subprocess

        def run(args):
            subprocess.run(args, check=True)
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Bounded subprocess execution in critical code", finding.Title);
        Assert.Contains("without shell=True", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_ReportsPythonSubprocessWithShellAsHighRisk()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "database");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "client.py"), """
        import subprocess

        def run(command):
            subprocess.run(command, shell=True, check=True)
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var finding = Assert.Single(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Command execution in critical code", finding.Title);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_ReportsEvalAsDynamicEvaluationNotCommandExecution()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "assets");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "CryptoLoader.js"), """
        export function loadCrypto() {
          return eval("require('crypto')");
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE016");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        var file = Assert.Single(artifact.Files);
        Assert.Contains(CodeCriticalityReason.DynamicCodeEvaluation, file.Reasons);
        Assert.DoesNotContain(CodeCriticalityReason.CommandExecution, file.Reasons);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportGoEvalDomainMethodsAsDynamicEvaluation()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "internal", "terraform");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "evaluate.go"), """
        package terraform

        func BuildScope(core Core, opts EvalOpts) (Scope, Diagnostics) {
            return core.Eval(opts)
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE016");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.DynamicCodeEvaluation));
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotReportPythonLiteralEvalAsDynamicEvaluation()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Path.Combine(fixture.Path, "src", "parsing");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "safe_parse.py"), """
        import ast

        def parse(value):
            return ast.literal_eval(value)
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE016");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.DoesNotContain(artifact.Files, file => file.Reasons.Contains(CodeCriticalityReason.DynamicCodeEvaluation));
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

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-CODE014" or "TRUST-CODE015" or "TRUST-CODE017");
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

    [Theory]
    [InlineData("playground/demo/CommandFixture.ts")]
    [InlineData("examples/demo/CommandFixture.ts")]
    [InlineData("samples/demo/CommandFixture.ts")]
    [InlineData("integration-test/app/CommandFixture.ts")]
    [InlineData("module/spring-boot-amqp/src/dockerTest/java/CommandFixture.java")]
    [InlineData("module/spring-boot-web-server/src/testFixtures/java/CommandFixture.java")]
    [InlineData("module/spring-boot-devtools/src/intTest/java/com/example/CommandFixture.java")]
    [InlineData("src/Hosting/Server.IntegrationTesting/src/Deployers/RemoteWindowsDeployer/RemoteWindowsDeployer.cs")]
    [InlineData("src/Http/Http.Extensions/gen/GeneratedEndpoint.cs")]
    [InlineData("src/Http/Http/perf/Microbenchmarks/CommandBenchmark.cs")]
    [InlineData("src/ProjectTemplates/Web.ProjectTemplates/content/EmptyWeb-CSharp/Program.cs")]
    [InlineData("src/Identity/testassets/Identity.DefaultUI.WebSite/wwwroot/lib/jquery/dist/jquery.js")]
    [InlineData("django/contrib/admin/static/admin/js/vendor/jquery/jquery.js")]
    [InlineData("src/Identity/UI/src/assets/V4/lib/jquery/dist/jquery.js")]
    [InlineData("fixtures/demo/CommandFixture.ts")]
    [InlineData("docs/demo/CommandFixture.ts")]
    public async Task CodeCriticalityAnalyzer_SkipsExampleAndPlaygroundSourceFiles(string relativePath)
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        import { execSync } from 'child_process'
        export function run() {
          execSync('whoami')
        }
        """);
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(artifact.Files);
    }

    [Fact]
    public async Task CodeCriticalityAnalyzer_DoesNotLetToolingFilesFillGeneralCriticalityFindings()
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, ".github", "skills", "release", "publish.ts");
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        var lines = Enumerable.Repeat(
            "try { child_process.execSync(token); authenticate(password); } catch (err) { }",
            405);
        File.WriteAllText(filePath, string.Join(Environment.NewLine, lines));
        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);

        var result = await new CodeCriticalityAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId is "TRUST-CODE004" or "TRUST-CODE005" or "TRUST-CODE006");
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE015");
        var artifact = Assert.IsType<CodeCriticalityArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Contains(artifact.Files, file => file.FilePath == ".github/skills/release/publish.ts");
    }
}

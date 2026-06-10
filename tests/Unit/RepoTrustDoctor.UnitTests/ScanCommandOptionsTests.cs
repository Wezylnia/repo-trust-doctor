using System.Globalization;
using System.IO;
using FsCheck.Xunit;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Shared;

namespace RepoTrustDoctor.UnitTests;

public sealed class ScanCommandOptionsTests
{
    [Theory]
    [InlineData("--version")]
    [InlineData("-v")]
    [InlineData("version")]
    public async Task RunAsync_VersionCommand_PrintsProductVersion(string versionArg)
    {
        using var writer = new StringWriter();
        var originalOut = Console.Out;
        Console.SetOut(writer);

        try
        {
            var exitCode = await CliProgram.RunAsync([versionArg], CancellationToken.None);

            Assert.Equal(0, exitCode);
            Assert.Contains(ProductInfo.CommandName, writer.ToString());
            Assert.Contains(ProductInfo.Version, writer.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public void TryParseScanOptions_DefaultValues_AreCorrect()
    {
        var args = new[] { "scan" };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(".", options.Target);
        Assert.Equal("console", options.Format);
        Assert.Null(options.OutputPath);
        Assert.False(options.ForceOutput);
        Assert.Equal(AnalysisDepth.Fast, options.Depth);
        Assert.Equal(TrustProfile.ProductionDependency, options.TrustProfile);
        Assert.Null(options.FailUnderScore);
        Assert.Null(options.FailOnSeverity);
    }

    [Fact]
    public void TryParseScanOptions_AllOptionsProvided_ParsesCorrectly()
    {
        var args = new[] { "scan", "myrepo", "--format", "json", "--output", "out.json", "--force", "--depth", "deep", "--profile", "Personal", "--fail-under", "80", "--fail-on-severity", "High" };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal("myrepo", options.Target);
        Assert.Equal("json", options.Format);
        Assert.Equal("out.json", options.OutputPath);
        Assert.True(options.ForceOutput);
        Assert.Equal(AnalysisDepth.Deep, options.Depth);
        Assert.Equal(TrustProfile.Personal, options.TrustProfile);
        Assert.Equal(80, options.FailUnderScore);
        Assert.Equal(Severity.High, options.FailOnSeverity);
    }

    [Fact]
    public void TryParseScanOptions_UnknownOption_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--unknown" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unknown option", error);
    }

    [Fact]
    public void TryParseScanOptions_UnsupportedFormat_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--format", "xml" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unsupported format", error);
    }

    [Fact]
    public void TryParseScanOptions_UnsupportedDepth_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--depth", "ultra" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unsupported depth", error);
    }

    [Fact]
    public void TryParseScanOptions_UnsupportedProfile_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--profile", "InvalidProfile" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unsupported profile", error);
    }

    [Fact]
    public void TryParseScanOptions_InvalidFailUnder_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--fail-under", "101" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("between 0 and 100", error);
    }

    [Fact]
    public void TryParseScanOptions_InvalidFailOnSeverity_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--fail-on-severity", "Severe" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unsupported severity", error);
    }

    [Fact]
    public void TryParseScanOptions_MissingOptionValue_ReturnsFalse()
    {
        var args = new[] { "scan", ".", "--output", "--force" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Missing value for option: --output", error);
    }

    [Fact]
    public void TryParseScanOptions_SecondPositionalArgument_ReturnsFalse()
    {
        var args = new[] { "scan", "first", "second" };
        var ok = CliProgram.TryParseScanOptions(args, out _, out var error);

        Assert.False(ok);
        Assert.Contains("Unexpected argument", error);
    }

    [Theory]
    [InlineData("console")]
    [InlineData("json")]
    [InlineData("markdown")]
    [InlineData("md")]
    [InlineData("sarif")]
    public void TryParseScanOptions_SupportedFormats_Accepted(string format)
    {
        var args = new[] { "scan", ".", "--format", format };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(format, options.Format);
    }

    [Theory]
    [InlineData("Personal", TrustProfile.Personal)]
    [InlineData("ProductionDependency", TrustProfile.ProductionDependency)]
    [InlineData("EnterpriseDependency", TrustProfile.EnterpriseDependency)]
    [InlineData("CiCdTool", TrustProfile.CiCdTool)]
    [InlineData("SecuritySensitiveDependency", TrustProfile.SecuritySensitiveDependency)]
    [InlineData("ContainerDependency", TrustProfile.ContainerDependency)]
    public void TryParseScanOptions_CanonicalProfiles_AreAccepted(string profile, TrustProfile expected)
    {
        var args = new[] { "scan", ".", "--profile", profile };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(expected, options.TrustProfile);
    }

    [Theory]
    [InlineData("production", TrustProfile.ProductionDependency)]
    [InlineData("enterprise", TrustProfile.EnterpriseDependency)]
    [InlineData("ci-cd", TrustProfile.CiCdTool)]
    [InlineData("security", TrustProfile.SecuritySensitiveDependency)]
    [InlineData("container", TrustProfile.ContainerDependency)]
    public void TryParseScanOptions_ProfileAliases_AreNormalized(string profile, TrustProfile expected)
    {
        var args = new[] { "scan", ".", "--profile", profile };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(expected, options.TrustProfile);
    }

    [Theory]
    [InlineData("Info", Severity.Info)]
    [InlineData("Low", Severity.Low)]
    [InlineData("Medium", Severity.Medium)]
    [InlineData("High", Severity.High)]
    [InlineData("Critical", Severity.Critical)]
    public void TryParseScanOptions_FailOnSeverity_AcceptsKnownSeverities(string severity, Severity expected)
    {
        var args = new[] { "scan", ".", "--fail-on-severity", severity };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(expected, options.FailOnSeverity);
    }

    [Fact]
    public void ComputeExitCode_ReturnsFour_WhenScoreIsBelowFailUnder()
    {
        var scan = CreateScan(score: 79);
        var options = CreateOptions(failUnderScore: 80);

        Assert.Equal(4, CliProgram.ComputeExitCode(scan, options));
    }

    [Fact]
    public void ComputeExitCode_ReturnsFour_WhenFindingMeetsFailOnSeverity()
    {
        var scan = CreateScan(findings: [CreateFinding(Severity.High)]);
        var options = CreateOptions(failOnSeverity: Severity.High);

        Assert.Equal(4, CliProgram.ComputeExitCode(scan, options));
    }

    [Fact]
    public void ComputeExitCode_ReturnsZero_WhenConfiguredGatesPass()
    {
        var scan = CreateScan(score: 90, findings: [CreateFinding(Severity.Low)]);
        var options = CreateOptions(failUnderScore: 80, failOnSeverity: Severity.High);

        Assert.Equal(0, CliProgram.ComputeExitCode(scan, options));
    }

    [Fact]
    public void ComputeExitCode_ReturnsThree_ForAvoidDecisionWithoutFailedGate()
    {
        var scan = CreateScan(decision: FinalDecisionKind.AvoidAsProductionDependency);
        var options = CreateOptions();

        Assert.Equal(3, CliProgram.ComputeExitCode(scan, options));
    }

    [Property(MaxTest = 100)]
    public void TryParseScanOptions_GeneratedRelativeTarget_RoundTrips(int value)
    {
        var target = $"repo-{value.ToString(CultureInfo.InvariantCulture)}";
        var args = new[] { "scan", target };

        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(target, options.Target);
    }

    private static ScanCommandOptions CreateOptions(int? failUnderScore = null, Severity? failOnSeverity = null)
    {
        return new ScanCommandOptions(
            ".",
            "console",
            null,
            false,
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            failUnderScore,
            failOnSeverity);
    }

    private static RepositoryScan CreateScan(
        int score = 100,
        FinalDecisionKind decision = FinalDecisionKind.SafeToTry,
        IReadOnlyList<Finding>? findings = null)
    {
        return new RepositoryScan(
            Guid.NewGuid(),
            ".",
            AnalysisDepth.Fast,
            TrustProfile.ProductionDependency,
            ProductInfo.Version,
            ModuleStatus.Completed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            [],
            findings ?? [],
            new TrustScore(score, [], new FinalDecision(decision, ["test"])));
    }

    private static Finding CreateFinding(Severity severity)
    {
        return new Finding(
            "TRUST-TEST001",
            "Test finding",
            AnalysisCategory.Security,
            severity,
            Confidence.High,
            "Test finding",
            [new Evidence("test", "test")],
            new Recommendation("Fix it."));
    }
}

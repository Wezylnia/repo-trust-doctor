using System.Globalization;
using FsCheck.Xunit;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.UnitTests;

public sealed class ScanCommandOptionsTests
{
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
    }

    [Fact]
    public void TryParseScanOptions_AllOptionsProvided_ParsesCorrectly()
    {
        var args = new[] { "scan", "myrepo", "--format", "json", "--output", "out.json", "--force", "--depth", "deep", "--profile", "Personal" };
        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal("myrepo", options.Target);
        Assert.Equal("json", options.Format);
        Assert.Equal("out.json", options.OutputPath);
        Assert.True(options.ForceOutput);
        Assert.Equal(AnalysisDepth.Deep, options.Depth);
        Assert.Equal(TrustProfile.Personal, options.TrustProfile);
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

    [Property(MaxTest = 100)]
    public void TryParseScanOptions_GeneratedRelativeTarget_RoundTrips(int value)
    {
        var target = $"repo-{value.ToString(CultureInfo.InvariantCulture)}";
        var args = new[] { "scan", target };

        var ok = CliProgram.TryParseScanOptions(args, out var options, out _);

        Assert.True(ok);
        Assert.Equal(target, options.Target);
    }
}

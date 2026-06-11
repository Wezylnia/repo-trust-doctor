using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Policies;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustPolicyTests
{
    [Theory]
    [InlineData(TrustProfile.Personal)]
    [InlineData(TrustProfile.ProductionDependency)]
    [InlineData(TrustProfile.SecuritySensitiveDependency)]
    public void ForProfile_ReturnsPolicyForEveryActiveProfile(TrustProfile profile)
    {
        var policy = TrustPolicyPresets.ForProfile(profile);

        Assert.Equal(profile, policy.Profile);
        Assert.NotEmpty(policy.Name);
        Assert.NotEmpty(policy.AllowedRegistries);
    }

    [Fact]
    public void StrictPolicy_IsStricterThanPersonalPolicy()
    {
        var personal = TrustPolicyPresets.ForProfile(TrustProfile.Personal);
        var strict = TrustPolicyPresets.ForProfile(TrustProfile.SecuritySensitiveDependency);

        Assert.True(strict.MinimumOverallScore > personal.MinimumOverallScore);
        Assert.Equal(UnknownLicenseHandling.Block, strict.UnknownLicenseHandling);
        Assert.True(strict.RequireReleaseChecksums);
    }

    [Fact]
    public void DefaultProductionPolicy_HasExpectedBaseline()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);

        Assert.Equal("Production Dependency", policy.Name);
        Assert.True(policy.RequireSecurityPolicy);
        Assert.Equal(Severity.High, policy.MaximumVulnerabilitySeverity);
    }

    [Theory]
    [InlineData(TrustProfile.EnterpriseDependency, TrustProfile.SecuritySensitiveDependency)]
    [InlineData(TrustProfile.CiCdTool, TrustProfile.ProductionDependency)]
    [InlineData(TrustProfile.ContainerDependency, TrustProfile.ProductionDependency)]
    public void ForProfile_MergesLegacyProfiles(TrustProfile legacy, TrustProfile expected)
    {
        var policy = TrustPolicyPresets.ForProfile(legacy);

        Assert.Equal(expected, policy.Profile);
    }
}

using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Policies;

namespace RepoTrustDoctor.UnitTests;

public sealed class TrustPolicyTests
{
    [Theory]
    [InlineData(TrustProfile.Personal)]
    [InlineData(TrustProfile.ProductionDependency)]
    [InlineData(TrustProfile.EnterpriseDependency)]
    [InlineData(TrustProfile.CiCdTool)]
    [InlineData(TrustProfile.SecuritySensitiveDependency)]
    [InlineData(TrustProfile.ContainerDependency)]
    public void ForProfile_ReturnsPolicyForEveryBuiltInProfile(TrustProfile profile)
    {
        var policy = TrustPolicyPresets.ForProfile(profile);

        Assert.Equal(profile, policy.Profile);
        Assert.NotEmpty(policy.Name);
        Assert.NotEmpty(policy.AllowedRegistries);
    }

    [Fact]
    public void EnterprisePolicy_IsStricterThanPersonalPolicy()
    {
        var personal = TrustPolicyPresets.ForProfile(TrustProfile.Personal);
        var enterprise = TrustPolicyPresets.ForProfile(TrustProfile.EnterpriseDependency);

        Assert.True(enterprise.MinimumOverallScore > personal.MinimumOverallScore);
        Assert.Equal(UnknownLicenseHandling.Block, enterprise.UnknownLicenseHandling);
        Assert.True(enterprise.RequireReleaseChecksums);
    }

    [Fact]
    public void DefaultProductionPolicy_HasExpectedBaseline()
    {
        var policy = TrustPolicyPresets.ForProfile(TrustProfile.ProductionDependency);

        Assert.Equal("Production Dependency", policy.Name);
        Assert.True(policy.RequireSecurityPolicy);
        Assert.Equal(Severity.High, policy.MaximumVulnerabilitySeverity);
    }
}

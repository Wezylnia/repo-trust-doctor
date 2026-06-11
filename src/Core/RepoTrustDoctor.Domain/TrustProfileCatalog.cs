namespace RepoTrustDoctor.Domain;

public static class TrustProfileCatalog
{
    public static IReadOnlyList<TrustProfile> ActiveProfiles { get; } =
    [
        TrustProfile.Personal,
        TrustProfile.ProductionDependency,
        TrustProfile.SecuritySensitiveDependency
    ];

    public static TrustProfile Normalize(TrustProfile profile) => profile switch
    {
        TrustProfile.CiCdTool => TrustProfile.ProductionDependency,
        TrustProfile.ContainerDependency => TrustProfile.ProductionDependency,
        TrustProfile.EnterpriseDependency => TrustProfile.SecuritySensitiveDependency,
        _ => profile
    };

    public static bool IsActive(TrustProfile profile) => ActiveProfiles.Contains(Normalize(profile));
}

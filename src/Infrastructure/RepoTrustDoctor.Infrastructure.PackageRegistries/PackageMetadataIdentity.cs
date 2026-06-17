using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public static class PackageMetadataIdentity
{
    public static string NormalizePackageName(DependencyEcosystem ecosystem, string packageName)
    {
        var trimmed = packageName.Trim();
        return ecosystem switch
        {
            DependencyEcosystem.Python => Regex.Replace(trimmed, "[-_.]+", "-").ToLowerInvariant(),
            DependencyEcosystem.Go or DependencyEcosystem.Maven or DependencyEcosystem.Swift => trimmed,
            _ => trimmed.ToLowerInvariant()
        };
    }
}

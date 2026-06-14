using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class NuGetDependencyCollector
{
    private static void AddPackage(
        string relativePath,
        string name,
        string? version,
        DependencyScope scope,
        string? lockfilePath,
        NuGetPackageLockResolver? lockResolver,
        DependencyInventoryState state)
    {
        var requestedVersion = DependencyInventorySupport.NormalizeVersion(version);
        var declaredVersion = NormalizeExactRange(requestedVersion);
        var resolvedVersion = string.Empty;
        var lockResolved = lockResolver is not null &&
                           lockResolver.TryResolve(name, out resolvedVersion);
        var effectiveVersion = lockResolved ? resolvedVersion : declaredVersion;
        var pinned = IsPinnedVersion(effectiveVersion);
        var prerelease = DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);
        var metadata = BuildVersionMetadata(requestedVersion, declaredVersion, lockResolved);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.NuGet,
            name,
            effectiveVersion,
            scope,
            relativePath,
            lockfilePath,
            true,
            pinned,
            prerelease,
            metadata));

        if (DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath))
        {
            return;
        }

        if (!pinned &&
            !ContainsMsBuildExpression(requestedVersion) &&
            state.TryMarkFinding($"nuget:TRUST-DEP004:{relativePath}:{name}"))
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP004",
                "NuGet dependency uses a floating or unpinned version",
                Severity.Medium,
                Confidence.High,
                $"NuGet dependency `{name}` is missing an exact pinned version.",
                "nuget-package",
                $"Package `{name}` version is `{DependencyInventorySupport.DisplayVersion(requestedVersion)}`.",
                relativePath,
                "Pin direct NuGet dependency versions or resolve them through Central Package Management."));
        }

        if (prerelease &&
            state.TryMarkFinding($"nuget:TRUST-DEP005:{relativePath}:{name}"))
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP005",
                "NuGet dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"NuGet dependency `{name}` uses prerelease version `{effectiveVersion}`.",
                "nuget-package",
                $"Package `{name}` version is `{effectiveVersion}`.",
                relativePath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private static IReadOnlyDictionary<string, string>? BuildVersionMetadata(
        string? requestedVersion,
        string? declaredVersion,
        bool lockResolved)
    {
        if (lockResolved)
        {
            return new Dictionary<string, string>
            {
                ["requestedVersion"] = requestedVersion ?? string.Empty,
                ["versionSource"] = "packages.lock.json"
            };
        }

        if (!string.Equals(requestedVersion, declaredVersion, StringComparison.Ordinal))
        {
            return new Dictionary<string, string>
            {
                ["requestedVersion"] = requestedVersion ?? string.Empty,
                ["versionSyntax"] = "exact-range"
            };
        }

        return null;
    }

    private static string? NormalizeExactRange(string? version)
    {
        if (version is not { Length: >= 3 } ||
            version[0] != '[' ||
            version[^1] != ']' ||
            version.Contains(',', StringComparison.Ordinal))
        {
            return version;
        }

        var inner = version[1..^1].Trim();
        return NuGetPackageLockResolver.IsExactVersion(inner) ? inner : version;
    }

    private static bool IsPinnedVersion(string? version) =>
        !ContainsMsBuildExpression(version) &&
        NuGetPackageLockResolver.IsExactVersion(version);
}

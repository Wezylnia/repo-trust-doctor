using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

internal sealed class EffectivePackageSourceResolver
{
    private static readonly HashSet<string> PublicRegistryHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "registry.npmjs.org",
        "npmjs.org",
        "www.npmjs.org",
        "api.nuget.org",
        "nuget.org",
        "pypi.org",
        "files.pythonhosted.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "rubygems.org",
        "crates.io",
        "pub.dev",
        "hex.pm",
        "packagist.org"
    };

    private readonly Dictionary<string, ScopedRegistryMapping> npmScopeMappings;

    public EffectivePackageSourceResolver(string repositoryPath)
    {
        npmScopeMappings = LoadNpmScopeMappings(repositoryPath);
    }

    public EffectivePackageSource Resolve(
        PackageRegistryMetadata package,
        DependencyPackageInfo? inventoryPackage,
        IReadOnlyList<DependencyPackageSourceInfo> packageSources)
    {
        var sourceKind = ReadSourceKind(package, inventoryPackage);
        if (!string.Equals(sourceKind, "registry", StringComparison.OrdinalIgnoreCase))
        {
            return EffectivePackageSource.Unknown(sourceKind);
        }

        return package.Ecosystem switch
        {
            DependencyEcosystem.Npm => ResolveNpm(package),
            DependencyEcosystem.NuGet => ResolveNuGet(packageSources),
            _ => ClassifyRegistry(package.SourceRegistry, null)
        };
    }

    public bool HasMatchingNpmScopeRegistry(string packageName) =>
        GetNpmScope(packageName) is { } scope && npmScopeMappings.ContainsKey(scope);

    private EffectivePackageSource ResolveNpm(PackageRegistryMetadata package)
    {
        if (GetNpmScope(package.Name) is { } scope &&
            npmScopeMappings.TryGetValue(scope, out var mapping))
        {
            return ClassifyRegistry(mapping.RegistryUrl, mapping.FilePath);
        }

        return ClassifyRegistry(package.SourceRegistry, null);
    }

    private static EffectivePackageSource ResolveNuGet(IReadOnlyList<DependencyPackageSourceInfo> packageSources)
    {
        var nugetSources = packageSources
            .Where(source => source.Ecosystem == DependencyEcosystem.NuGet)
            .ToArray();
        if (nugetSources.Length == 0)
        {
            return EffectivePackageSource.Unknown("nuget-source-unavailable");
        }

        if (nugetSources.Length == 1)
        {
            return ClassifyRegistry(nugetSources[0].Source, nugetSources[0].FilePath);
        }

        var publicSources = nugetSources
            .Where(source => IsPublicRegistry(source.Source))
            .ToArray();
        var privateSources = nugetSources
            .Where(source => !source.IsLocal && !IsPublicRegistry(source.Source))
            .ToArray();

        return publicSources.Length switch
        {
            0 when privateSources.Length > 0 => EffectivePackageSource.Private(privateSources[0].Source, privateSources[0].FilePath),
            > 0 when privateSources.Length == 0 => EffectivePackageSource.Public(publicSources[0].Source, publicSources[0].FilePath),
            _ => EffectivePackageSource.Unknown("mixed-nuget-sources")
        };
    }

    private static EffectivePackageSource ClassifyRegistry(string? registry, string? evidencePath)
    {
        if (string.IsNullOrWhiteSpace(registry))
        {
            return EffectivePackageSource.Unknown("registry-missing");
        }

        return IsPublicRegistry(registry)
            ? EffectivePackageSource.Public(registry, evidencePath)
            : EffectivePackageSource.Private(registry, evidencePath);
    }

    private static bool IsPublicRegistry(string registry)
    {
        if (Uri.TryCreate(registry, UriKind.Absolute, out var uri))
        {
            return PublicRegistryHosts.Contains(uri.Host);
        }

        return PublicRegistryHosts.Contains(registry.Trim());
    }

    private static string ReadSourceKind(
        PackageRegistryMetadata package,
        DependencyPackageInfo? inventoryPackage)
    {
        if (inventoryPackage?.Metadata?.TryGetValue("sourceKind", out var inventoryKind) == true &&
            !string.IsNullOrWhiteSpace(inventoryKind))
        {
            return inventoryKind;
        }

        if (package.Metadata?.TryGetValue("sourceKind", out var metadataKind) == true &&
            !string.IsNullOrWhiteSpace(metadataKind))
        {
            return metadataKind;
        }

        return "registry";
    }

    private static Dictionary<string, ScopedRegistryMapping> LoadNpmScopeMappings(string repositoryPath)
    {
        var mappings = new Dictionary<string, ScopedRegistryMapping>(StringComparer.Ordinal);
        foreach (var npmrc in RepositoryFileSystem.EnumerateFiles(repositoryPath, ".npmrc"))
        {
            if (!TryReadText(npmrc, out var content))
            {
                continue;
            }

            var relativePath = Path.GetRelativePath(repositoryPath, npmrc).Replace('\\', '/');
            foreach (var line in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#') || trimmed.StartsWith(';'))
                {
                    continue;
                }

                var separatorIndex = trimmed.IndexOf(":registry", StringComparison.Ordinal);
                if (separatorIndex <= 1)
                {
                    continue;
                }

                var scope = trimmed[..separatorIndex];
                var remainder = trimmed[(separatorIndex + ":registry".Length)..].TrimStart();
                if (!remainder.StartsWith("=", StringComparison.Ordinal))
                {
                    continue;
                }

                var registryUrl = remainder[1..].Trim();
                if (registryUrl.Length == 0)
                {
                    continue;
                }

                mappings[scope] = new ScopedRegistryMapping(scope, registryUrl, relativePath);
            }
        }

        return mappings;
    }

    private static string? GetNpmScope(string packageName)
    {
        if (!packageName.StartsWith("@", StringComparison.Ordinal))
        {
            return null;
        }

        var slash = packageName.IndexOf('/');
        return slash > 1 ? packageName[..slash] : null;
    }

    private static bool TryReadText(string path, out string content)
    {
        content = string.Empty;
        if (!RepositoryFileSystem.CanReadAsText(path))
        {
            return false;
        }

        try
        {
            content = File.ReadAllText(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private sealed record ScopedRegistryMapping(string Scope, string RegistryUrl, string FilePath);
}

internal sealed record EffectivePackageSource(
    string? RegistryUrl,
    bool IsPublic,
    bool IsPrivate,
    bool IsUnknown,
    string? EvidencePath,
    string Reason)
{
    public static EffectivePackageSource Public(string registryUrl, string? evidencePath) =>
        new(registryUrl, true, false, false, evidencePath, "public-registry");

    public static EffectivePackageSource Private(string registryUrl, string? evidencePath) =>
        new(registryUrl, false, true, false, evidencePath, "private-registry");

    public static EffectivePackageSource Unknown(string reason) =>
        new(null, false, false, true, null, reason);
}

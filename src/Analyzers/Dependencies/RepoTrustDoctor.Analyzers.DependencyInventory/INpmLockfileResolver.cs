namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal interface INpmLockfileResolver
{
    string VersionSource { get; }

    bool TryResolve(
        string manifestDirectory,
        string packageName,
        string? requestedVersion,
        out string version);
}

internal static class NpmLockfileResolverFactory
{
    public static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out INpmLockfileResolver? resolver)
    {
        var fileName = Path.GetFileName(lockfilePath);
        if (fileName.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase))
        {
            var loaded = NpmPackageLockResolver.TryLoad(lockfilePath, relativePath, warnings, out var packageLock);
            resolver = packageLock;
            return loaded;
        }

        if (fileName.Equals("pnpm-lock.yaml", StringComparison.OrdinalIgnoreCase))
        {
            var loaded = PnpmLockfileResolver.TryLoad(lockfilePath, relativePath, warnings, out var pnpmLock);
            resolver = pnpmLock;
            return loaded;
        }

        if (fileName.Equals("yarn.lock", StringComparison.OrdinalIgnoreCase))
        {
            var loaded = YarnLockfileResolver.TryLoad(lockfilePath, relativePath, warnings, out var yarnLock);
            resolver = yarnLock;
            return loaded;
        }

        resolver = null;
        return false;
    }
}

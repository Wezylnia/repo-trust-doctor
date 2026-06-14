using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class NuGetDependencyCollector
{
    private static IReadOnlyDictionary<string, string> IndexLockfilesByDirectory(
        IEnumerable<string> lockfiles)
    {
        var byDirectory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lockfile in lockfiles)
        {
            var directory = Path.GetDirectoryName(lockfile);
            if (directory is not null)
            {
                byDirectory[directory] = lockfile;
            }
        }

        return byDirectory;
    }

    private static string? FindProjectLockfile(
        string projectPath,
        IReadOnlyDictionary<string, string> lockfilesByDirectory) =>
        Path.GetDirectoryName(projectPath) is { } directory &&
        lockfilesByDirectory.TryGetValue(directory, out var lockfile)
            ? lockfile
            : null;

    private static NuGetPackageLockResolver? GetLockResolver(
        AnalysisContext context,
        string? lockfile,
        Dictionary<string, NuGetPackageLockResolver?> resolvers,
        DependencyInventoryState state)
    {
        if (lockfile is null)
        {
            return null;
        }

        if (resolvers.TryGetValue(lockfile, out var resolver))
        {
            return resolver;
        }

        NuGetPackageLockResolver.TryLoad(
            lockfile,
            DependencyInventorySupport.Relative(context, lockfile),
            state.Warnings,
            out resolver);
        resolvers[lockfile] = resolver;
        return resolver;
    }

    private static void AddMissingLockfileFinding(
        AnalysisContext context,
        IReadOnlyList<string> packageProjects,
        IReadOnlyDictionary<string, string> lockfilesByDirectory,
        DependencyInventoryState state)
    {
        var missingProjects = packageProjects
            .Where(project => FindProjectLockfile(project, lockfilesByDirectory) is null)
            .Select(project => DependencyInventorySupport.Relative(context, project))
            .ToArray();
        if (missingProjects.Length == 0)
        {
            return;
        }

        var evidence = missingProjects
            .Take(25)
            .Select(project => new Evidence(
                "package-manifest",
                "This NuGet project has package references but no adjacent packages.lock.json.",
                project))
            .ToArray();
        var message = missingProjects.Length == 1
            ? "NuGet project does not use lockfile"
            : $"{missingProjects.Length} NuGet projects do not use project-local lockfiles";

        state.Findings.Add(new Finding(
            "TRUST-DEP002",
            "NuGet project does not use lockfile",
            AnalysisCategory.Dependencies,
            Severity.Low,
            Confidence.Medium,
            message,
            evidence,
            new Recommendation(
                "Enable NuGet lock files and restore locked mode, then commit a packages.lock.json beside each project that declares packages.")));
    }
}

using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class PubDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["pubspec.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Pub,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var pubspec in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pubspec.yaml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePubspec(context, pubspec, state);
        }
    }

    private static void AnalyzePubspec(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Pub, relativePath, "pubspec.yaml"));

        if (!HasSiblingLockfile(filePath))
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP037",
                "Dart project does not have a pubspec.lock file",
                Severity.Medium,
                Confidence.High,
                "A pubspec.yaml file exists but no pubspec.lock was found.",
                "package-manifest",
                "No pubspec.lock file was found alongside pubspec.yaml.",
                relativePath,
                "Run 'dart pub get' and commit pubspec.lock to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        DependencyScope currentScope = DependencyScope.Production;
        bool inDeps = false;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            // Check section headers first
            if (line == "dependencies:")
            {
                currentScope = DependencyScope.Production;
                inDeps = true;
                continue;
            }
            if (line == "dev_dependencies:")
            {
                currentScope = DependencyScope.Development;
                inDeps = true;
                continue;
            }

            // Exit dependency section when we hit a non-indented line
            if (inDeps && !rawLine.StartsWith(" ", StringComparison.Ordinal))
            {
                inDeps = false;
                continue;
            }

            if (!inDeps)
            {
                continue;
            }

            // Match indented dependency: "  package_name: version_constraint"
            var match = PubDependencyPattern().Match(rawLine);
            if (!match.Success)
            {
                continue;
            }

            var pkgName = match.Groups["name"].Value;
            var constraint = match.Groups["constraint"].Success ? match.Groups["constraint"].Value.Trim('"', '\'') : null;

            var isPinned = constraint != null && ExactVersionPattern().IsMatch(constraint);
            var isPrerelease = constraint != null && DependencyInventorySupport.IsPrereleaseVersion(constraint);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Pub,
                pkgName,
                constraint,
                currentScope,
                relativePath,
                null,
                true,
                isPinned,
                isPrerelease,
                null));

            if (!isPinned && constraint != null)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP038",
                    "Dart dependency uses a non-exact version constraint",
                    Severity.Medium,
                    Confidence.High,
                    $"Dart dependency '{pkgName}' uses a version constraint instead of an exact version.",
                    "pub-dependency",
                    $"Package '{pkgName}' has version constraint '{constraint}'.",
                    relativePath,
                    "Use exact version constraints with a committed pubspec.lock for reproducible builds."));
            }
        }
    }

    [GeneratedRegex(@"^\s+(?<name>[^:\s]+):\s*(?<constraint>\S+)")]
    private static partial Regex PubDependencyPattern();

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactVersionPattern();

    private static bool HasSiblingLockfile(string pubspecPath)
    {
        var directory = Path.GetDirectoryName(pubspecPath);
        return directory is not null && File.Exists(Path.Combine(directory, "pubspec.lock"));
    }
}

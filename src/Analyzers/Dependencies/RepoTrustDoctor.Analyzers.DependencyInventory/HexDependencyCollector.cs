using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class HexDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["mix.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Hex,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var mixExs in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "mix.exs"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeMixExs(context, mixExs, state);
        }
    }

    private static void AnalyzeMixExs(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Hex, relativePath, "mix.exs"));
        var lockfilePath = Path.Combine(Path.GetDirectoryName(filePath)!, "mix.lock");
        var hasSiblingLockfile = File.Exists(lockfilePath);
        var lockfile = hasSiblingLockfile
            ? HexLockfileResolver.TryCreate(
                lockfilePath,
                DependencyInventorySupport.Relative(context, lockfilePath),
                state)
            : null;

        if (!hasSiblingLockfile)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP040",
                "Elixir project does not have a mix.lock file",
                Severity.Medium,
                Confidence.High,
                "A mix.exs file exists but no mix.lock was found.",
                "package-manifest",
                "No mix.lock file was found alongside mix.exs.",
                relativePath,
                "Run 'mix deps.get' and commit mix.lock to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            // Match: {:package_name, "~> 1.0"},
            // or: {:package_name, ">= 1.0.0"},
            // or: {:package_name, git: "https://..."},
            // or: {:package_name, path: "../local"},
            var match = HexDependencyPattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var pkgName = match.Groups["name"].Value;
            var constraint = match.Groups["constraint"].Success ? match.Groups["constraint"].Value : null;
            var isGit = match.Groups["git"].Success;
            var isPath = match.Groups["path"].Success;
            var path = isPath ? match.Groups["path"].Value : null;
            var resolvedVersion = string.Empty;
            var resolved = constraint != null &&
                           lockfile is not null &&
                           lockfile.TryResolve(pkgName, out resolvedVersion);
            var effectiveVersion = resolved ? resolvedVersion : constraint;

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (isGit) metadata["sourceKind"] = "git";
            if (isPath) metadata["sourceKind"] = "path";
            if (resolved)
            {
                metadata["requestedVersion"] = constraint!;
                metadata["versionSource"] = "mix.lock";
            }

            var isPinned = effectiveVersion != null && ExactHexVersionPattern().IsMatch(effectiveVersion);
            var isPrerelease = effectiveVersion != null && DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Hex,
                pkgName,
                effectiveVersion,
                DependencyScope.Production,
                relativePath,
                resolved ? lockfile!.RelativePath : null,
                true,
                isPinned,
                isPrerelease,
                metadata.Count > 0 ? metadata : null));

            var reportsPathSource = isPath &&
                                    !DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath) &&
                                    !IsRepositoryLocalPath(context.RepositoryPath, filePath, path!);
            if (isGit || reportsPathSource)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP042",
                    "Elixir dependency uses a non-Hex source",
                    Severity.Medium,
                    Confidence.High,
                    $"Elixir dependency '{pkgName}' uses a {(isGit ? "Git" : "path")} source instead of Hex.",
                    "hex-source",
                    $"Dependency '{pkgName}' uses a non-Hex source.",
                    relativePath,
                    "Review non-Hex dependency sources and prefer Hex packages with pinned versions when possible."));
            }

            if (!isPinned &&
                constraint != null &&
                !DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath))
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP041",
                    "Elixir dependency uses a non-exact version constraint",
                    Severity.Medium,
                    Confidence.High,
                    $"Elixir dependency '{pkgName}' is not resolved to an exact version.",
                    "hex-dependency",
                    hasSiblingLockfile
                        ? $"Dependency '{pkgName}' has constraint '{constraint}', but mix.lock does not resolve it."
                        : $"Dependency '{pkgName}' has version constraint '{constraint}' without a mix.lock resolution.",
                    relativePath,
                    "Commit an up-to-date mix.lock that resolves the dependency to an exact version."));
            }
        }
    }

    [GeneratedRegex(@"\{:(?<name>[^,]+),\s*(?:""(?<constraint>[^""]+)"")?(?:.*git:\s*""(?<git>[^""]+)"")?(?:.*path:\s*""(?<path>[^""]+)"")?")]
    private static partial Regex HexDependencyPattern();

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactHexVersionPattern();

    private static bool IsRepositoryLocalPath(string repositoryPath, string manifestPath, string dependencyPath)
    {
        var manifestDirectory = Path.GetDirectoryName(manifestPath);
        if (manifestDirectory is null)
        {
            return false;
        }

        var resolvedPath = Path.GetFullPath(Path.Combine(manifestDirectory, dependencyPath));
        var resolvedRepository = Path.GetFullPath(repositoryPath);
        var relative = Path.GetRelativePath(resolvedRepository, resolvedPath);
        return relative != ".." &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
               !Path.IsPathRooted(relative);
    }
}

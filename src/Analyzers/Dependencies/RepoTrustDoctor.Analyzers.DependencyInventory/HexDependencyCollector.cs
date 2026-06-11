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

        if (!HasSiblingLockfile(filePath))
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

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (isGit) metadata["sourceKind"] = "git";
            if (isPath) metadata["sourceKind"] = "path";

            var isPinned = constraint != null && ExactHexVersionPattern().IsMatch(constraint);
            var isPrerelease = constraint != null && DependencyInventorySupport.IsPrereleaseVersion(constraint);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Hex,
                pkgName,
                constraint,
                DependencyScope.Production,
                relativePath,
                null,
                true,
                isPinned,
                isPrerelease,
                metadata.Count > 0 ? metadata : null));

            if (isGit || isPath)
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

            if (!isPinned && constraint != null)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP041",
                    "Elixir dependency uses a non-exact version constraint",
                    Severity.Medium,
                    Confidence.High,
                    $"Elixir dependency '{pkgName}' uses a version constraint instead of an exact version.",
                    "hex-dependency",
                    $"Dependency '{pkgName}' has version constraint '{constraint}'.",
                    relativePath,
                    "Use exact version constraints with a committed mix.lock for reproducible builds."));
            }
        }
    }

    [GeneratedRegex(@"\{:(?<name>[^,]+),\s*(?:""(?<constraint>[^""]+)"")?(?:.*git:\s*""(?<git>[^""]+)"")?(?:.*path:\s*""(?<path>[^""]+)"")?")]
    private static partial Regex HexDependencyPattern();

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactHexVersionPattern();

    private static bool HasSiblingLockfile(string mixExsPath)
    {
        var directory = Path.GetDirectoryName(mixExsPath);
        return directory is not null && File.Exists(Path.Combine(directory, "mix.lock"));
    }
}

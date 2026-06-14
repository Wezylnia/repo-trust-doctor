using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class SwiftPmCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Package.resolved"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Swift,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var packageSwift in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Package.swift"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePackageSwift(context, packageSwift, state);
        }
    }

    private static void AnalyzePackageSwift(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Swift, relativePath, "Package.swift"));

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        if (RequiresResolvedFile(content, relativePath) && !HasResolvedFile(filePath))
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP043",
                "Swift executable package does not have a Package.resolved file",
                Severity.Medium,
                Confidence.High,
                "A Swift executable package exists but no Package.resolved was found.",
                "package-manifest",
                "No Package.resolved file was found for the executable package.",
                relativePath,
                "Commit Package.resolved for reproducible executable builds."));
        }

        foreach (Match match in SwiftPackagePattern().Matches(content))
        {
            if (IsCommentedOut(content, match.Index))
            {
                continue;
            }

            var url = match.Groups["url"].Success ? match.Groups["url"].Value : null;
            var path = match.Groups["path"].Success ? match.Groups["path"].Value : null;
            var version = match.Groups["version"].Success ? match.Groups["version"].Value : null;
            var isBranch = match.Groups["branch"].Success;
            var isExact = match.Value.Contains("exact:", StringComparison.Ordinal);

            var pkgName = url ?? path ?? "unknown";
            var constraint = isBranch ? $"branch:{match.Groups["branch"].Value}" : version;

            var isPinned = isExact && version != null;
            var isPrerelease = version != null && DependencyInventorySupport.IsPrereleaseVersion(version);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Swift,
                pkgName,
                constraint,
                DependencyScope.Production,
                relativePath,
                null,
                true,
                isPinned,
                isPrerelease,
                isBranch ? new Dictionary<string, string> { ["sourceKind"] = "branch" } : null));

            if (isBranch)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP044",
                    "Swift package uses a branch-based dependency",
                    Severity.Medium,
                    Confidence.High,
                    $"Swift package dependency references a branch instead of a version.",
                    "swift-branch",
                    $"Dependency uses branch '{match.Groups["branch"].Value}'.",
                    relativePath,
                    "Prefer version-based dependencies with a committed Package.resolved for reproducible builds."));
            }
        }
    }

    [GeneratedRegex(@"\.package\s*\(\s*(?:url\s*:\s*""(?<url>[^""]+)""|path\s*:\s*""(?<path>[^""]+)"")(?:\s*,\s*(?:from|exact)\s*:\s*""(?<version>[^""]+)"")?(?:\s*,\s*branch\s*:\s*""(?<branch>[^""]+)"")?")]
    private static partial Regex SwiftPackagePattern();

    private static bool RequiresResolvedFile(string content, string relativePath) =>
        !RepositoryPathClassifier.IsNonProductionEvidencePath(relativePath) &&
        content.Contains(".executable(", StringComparison.Ordinal);

    private static bool HasResolvedFile(string packageSwiftPath)
    {
        var directory = Path.GetDirectoryName(packageSwiftPath);
        return directory is not null &&
               (File.Exists(Path.Combine(directory, "Package.resolved")) ||
                File.Exists(Path.Combine(directory, ".swiftpm", "Package.resolved")));
    }

    private static bool IsCommentedOut(string content, int matchIndex)
    {
        var lineStart = content.LastIndexOf('\n', Math.Max(0, matchIndex - 1));
        var prefix = content[(lineStart + 1)..matchIndex].TrimStart();
        return prefix.StartsWith("//", StringComparison.Ordinal);
    }
}

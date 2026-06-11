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

        var hasLockfile = state.Lockfiles.Any(l => l.Ecosystem == DependencyEcosystem.Swift);
        if (!hasLockfile)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP043",
                "Swift package does not have a Package.resolved file",
                Severity.Medium,
                Confidence.High,
                "A Package.swift file exists but no Package.resolved was found.",
                "package-manifest",
                "No Package.resolved file was found alongside Package.swift.",
                relativePath,
                "Commit Package.resolved to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            // Match: .package(url: "https://...", from: "1.0.0"),
            // or: .package(url: "https://...", exact: "1.2.3"),
            // or: .package(url: "https://...", branch: "main"),
            // or: .package(path: "../local"),
            var match = SwiftPackagePattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var url = match.Groups["url"].Success ? match.Groups["url"].Value : null;
            var path = match.Groups["path"].Success ? match.Groups["path"].Value : null;
            var version = match.Groups["version"].Success ? match.Groups["version"].Value : null;
            var isBranch = match.Groups["branch"].Success;
            var isExact = line.Contains("exact:", StringComparison.Ordinal);

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
}

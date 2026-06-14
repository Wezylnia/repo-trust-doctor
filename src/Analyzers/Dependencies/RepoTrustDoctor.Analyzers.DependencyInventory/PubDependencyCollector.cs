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

        var hasSiblingLockfile = HasSiblingLockfile(filePath);
        var lockfile = hasSiblingLockfile
            ? CreateLockfileResolver(context, filePath, state)
            : null;
        var reportReproducibilityFindings =
            !hasSiblingLockfile &&
            IsLikelyPubApplicationManifest(filePath, relativePath) &&
            !IsLowSignalPubPath(relativePath) &&
            !DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath);

        if (reportReproducibilityFindings)
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
        var dependencyIndent = 2;

        for (var index = 0; index < lines.Length; index++)
        {
            var rawLine = lines[index];
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
            if (inDeps && CountLeadingSpaces(rawLine) == 0)
            {
                inDeps = false;
                continue;
            }

            if (!inDeps)
            {
                continue;
            }

            // Match direct dependency entries only. Nested YAML properties such as
            // "sdk: flutter" or "path: ../pkg" belong to the previous package.
            var match = PubDependencyPattern().Match(rawLine);
            if (!match.Success || CountLeadingSpaces(rawLine) != dependencyIndent)
            {
                continue;
            }

            var pkgName = match.Groups["name"].Value;
            if (IsPubDependencyMetadataKey(pkgName))
            {
                continue;
            }

            var inlineConstraint = match.Groups["constraint"].Success ? match.Groups["constraint"].Value.Trim() : string.Empty;
            var dependencyInfo = inlineConstraint.Length > 0
                ? new PubDependencyInfo(NormalizePubConstraint(inlineConstraint), null)
                : ReadPubDependencyBlock(lines, index + 1, dependencyIndent);

            var constraint = dependencyInfo.Constraint;
            var resolvedVersion = string.Empty;
            var resolved = dependencyInfo.Metadata?.ContainsKey("sourceKind") != true &&
                           lockfile is not null &&
                           lockfile.TryResolve(pkgName, out resolvedVersion);
            var effectiveVersion = resolved ? resolvedVersion : constraint;
            var metadata = dependencyInfo.Metadata is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(
                    dependencyInfo.Metadata,
                    StringComparer.OrdinalIgnoreCase);
            if (resolved)
            {
                metadata["requestedVersion"] = constraint ?? string.Empty;
                metadata["versionSource"] = "pubspec.lock";
            }

            var isPinned = resolved || effectiveVersion != null && ExactVersionPattern().IsMatch(effectiveVersion);
            var isPrerelease = effectiveVersion != null &&
                               DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Pub,
                pkgName,
                effectiveVersion,
                currentScope,
                relativePath,
                resolved ? lockfile!.RelativePath : null,
                true,
                isPinned,
                isPrerelease,
                metadata.Count > 0 ? metadata : null));

            if (!isPinned && constraint != null && reportReproducibilityFindings)
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

    private static PubDependencyInfo ReadPubDependencyBlock(string[] lines, int startIndex, int dependencyIndent)
    {
        string? constraint = null;
        Dictionary<string, string>? metadata = null;

        for (var index = startIndex; index < lines.Length; index++)
        {
            var rawLine = lines[index];
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            if (CountLeadingSpaces(rawLine) <= dependencyIndent)
            {
                break;
            }

            var property = PubDependencyBlockPropertyPattern().Match(rawLine);
            if (!property.Success)
            {
                continue;
            }

            var key = property.Groups["name"].Value;
            var value = NormalizePubConstraint(property.Groups["value"].Value);

            if (key.Equals("version", StringComparison.OrdinalIgnoreCase))
            {
                constraint = value;
            }
            else if (key.Equals("sdk", StringComparison.OrdinalIgnoreCase))
            {
                metadata ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                metadata["sourceKind"] = "sdk";
            }
            else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
            {
                metadata ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                metadata["sourceKind"] = "path";
            }
            else if (key.Equals("git", StringComparison.OrdinalIgnoreCase))
            {
                metadata ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                metadata["sourceKind"] = "git";
            }
        }

        return new PubDependencyInfo(constraint, metadata);
    }

    private static string? NormalizePubConstraint(string value)
    {
        var normalized = value.Trim().Trim('"', '\'');
        if (normalized.Length == 0)
        {
            return null;
        }

        if (normalized is "{}" or "[]" or "|")
        {
            return null;
        }

        return normalized;
    }

    private static bool IsPubDependencyMetadataKey(string packageName) =>
        packageName.Equals("sdk", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("path", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("git", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("hosted", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("version", StringComparison.OrdinalIgnoreCase);

    private static bool IsLowSignalPubPath(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/');
        return normalized.StartsWith("dev/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/dev/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/benchmarks/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/benchmark/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/integration_tests/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/integration_test/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/customer_testing/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/devicelab/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("ci/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/ci/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("tools/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/tools/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("testing/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/testing/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("example/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("/example/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("test_private", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("forbidden_from_release_tests", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyPubApplicationManifest(string filePath, string relativePath)
    {
        if (relativePath.Equals("pubspec.yaml", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var directory = Path.GetDirectoryName(filePath);
        if (directory is null)
        {
            return false;
        }

        return Directory.Exists(Path.Combine(directory, "android")) ||
               Directory.Exists(Path.Combine(directory, "ios")) ||
               Directory.Exists(Path.Combine(directory, "web")) ||
               Directory.Exists(Path.Combine(directory, "macos")) ||
               Directory.Exists(Path.Combine(directory, "linux")) ||
               Directory.Exists(Path.Combine(directory, "windows")) ||
               File.Exists(Path.Combine(directory, "lib", "main.dart"));
    }

    private static int CountLeadingSpaces(string value)
    {
        var count = 0;
        while (count < value.Length && value[count] == ' ')
        {
            count++;
        }

        return count;
    }

    [GeneratedRegex(@"^\s+(?<name>[^:\s]+):\s*(?<constraint>.*)$")]
    private static partial Regex PubDependencyPattern();

    [GeneratedRegex(@"^\s+(?<name>[^:\s]+):\s*(?<value>.*)$")]
    private static partial Regex PubDependencyBlockPropertyPattern();

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactVersionPattern();

    private static bool HasSiblingLockfile(string pubspecPath)
    {
        var directory = Path.GetDirectoryName(pubspecPath);
        return directory is not null && File.Exists(Path.Combine(directory, "pubspec.lock"));
    }

    private static PubLockfileResolver? CreateLockfileResolver(
        AnalysisContext context,
        string pubspecPath,
        DependencyInventoryState state)
    {
        var lockfilePath = Path.Combine(Path.GetDirectoryName(pubspecPath)!, "pubspec.lock");
        return PubLockfileResolver.TryCreate(
            lockfilePath,
            DependencyInventorySupport.Relative(context, lockfilePath),
            state);
    }

    private sealed record PubDependencyInfo(string? Constraint, IReadOnlyDictionary<string, string>? Metadata);
}

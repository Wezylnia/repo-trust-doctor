using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class GoDependencyCollector : IDependencyInventoryCollector
{
    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var goMod in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "go.mod"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeGoMod(context, goMod, state);
        }
    }

    private static void AnalyzeGoMod(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        var suppressManifestHygieneFindings = IsLowSignalGoManifest(relativePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Go, relativePath, "go.mod"));

        var hasGoSum = HasGoSum(context, filePath);
        if (!hasGoSum && !suppressManifestHygieneFindings)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP022",
                "Go module does not have a go.sum file",
                Severity.Medium,
                Confidence.High,
                "A go.mod file exists but no go.sum was found alongside it.",
                "package-manifest",
                "No go.sum file was found alongside go.mod.",
                relativePath,
                "Run 'go mod tidy' and commit go.sum to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        var inRequireBlock = false;
        string? modulePath = null;
        var replaceDirectives = new List<string>();
        var localReplacementModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directPseudoVersions = new List<(string ModulePath, string Version)>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (line is "require (" or "require(")
            {
                inRequireBlock = true;
                continue;
            }

            if (inRequireBlock && line == ")")
            {
                inRequireBlock = false;
                continue;
            }

            if (line.StartsWith("module ", StringComparison.Ordinal))
            {
                modulePath = line["module ".Length..].Trim();
                continue;
            }

            if (line.StartsWith("require ", StringComparison.Ordinal))
            {
                ParseSingleRequire(relativePath, line["require ".Length..].Trim(), state, directPseudoVersions, suppressManifestHygieneFindings);
                continue;
            }

            if (inRequireBlock)
            {
                ParseSingleRequire(relativePath, line, state, directPseudoVersions, suppressManifestHygieneFindings);
            }

            if (line.StartsWith("replace ", StringComparison.Ordinal))
            {
                var replace = ParseReplaceDirective(line);
                if (replace is not null &&
                    IsLocalReplacementInsideRepository(context.RepositoryPath, filePath, replace.Target))
                {
                    localReplacementModules.Add(replace.ModulePath);
                    continue;
                }

                replaceDirectives.Add(line);
            }
        }

        if (!suppressManifestHygieneFindings)
        {
            AddReplaceDirectiveFinding(relativePath, replaceDirectives, state);
            AddPseudoVersionFinding(
                relativePath,
                directPseudoVersions
                    .Where(dependency => !localReplacementModules.Contains(dependency.ModulePath))
                    .ToArray(),
                state);
        }

        if (modulePath != null && ModuleLooksPseudoVersion(modulePath, lines))
        {
            // Pseudo-version detection is done at the package level below
        }
    }

    private static bool HasGoSum(AnalysisContext context, string goModPath)
    {
        var directory = Path.GetDirectoryName(goModPath);
        if (directory == null)
        {
            return false;
        }

        var goSumPath = Path.Combine(directory, "go.sum");
        return File.Exists(goSumPath);
    }

    private static bool IsLowSignalGoManifest(string relativePath) =>
        DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath) ||
        RepositoryPathClassifier.Normalize(relativePath).Contains("/cryptotest/", StringComparison.OrdinalIgnoreCase);

    private static GoReplaceDirective? ParseReplaceDirective(string line)
    {
        var body = line["replace ".Length..].Trim();
        var split = body.Split(["=>"], StringSplitOptions.TrimEntries);
        if (split.Length != 2)
        {
            return null;
        }

        var leftParts = split[0].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var rightParts = split[1].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (leftParts.Length == 0 || rightParts.Length == 0)
        {
            return null;
        }

        return new GoReplaceDirective(leftParts[0], rightParts[0]);
    }

    private static bool IsLocalReplacementInsideRepository(string repositoryPath, string goModPath, string target)
    {
        if (!LooksLikeLocalPath(target))
        {
            return false;
        }

        var manifestDirectory = Path.GetDirectoryName(goModPath);
        if (manifestDirectory is null)
        {
            return false;
        }

        var resolvedTarget = Path.GetFullPath(
            Path.IsPathRooted(target)
                ? target
                : Path.Combine(manifestDirectory, target));
        var resolvedRepository = Path.GetFullPath(repositoryPath);

        return IsSameOrChildPath(resolvedTarget, resolvedRepository);
    }

    private static bool LooksLikeLocalPath(string target) =>
        target is "." or ".." ||
        target.StartsWith("./", StringComparison.Ordinal) ||
        target.StartsWith("../", StringComparison.Ordinal) ||
        target.StartsWith(".\\", StringComparison.Ordinal) ||
        target.StartsWith("..\\", StringComparison.Ordinal) ||
        Path.IsPathRooted(target);

    private static bool IsSameOrChildPath(string path, string parent)
    {
        var normalizedPath = TrimTrailingDirectorySeparators(path);
        var normalizedParent = TrimTrailingDirectorySeparators(parent);
        return string.Equals(normalizedPath, normalizedParent, PathComparison) ||
               normalizedPath.StartsWith(EnsureTrailingDirectorySeparator(normalizedParent), PathComparison);
    }

    private static string EnsureTrailingDirectorySeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;

    private static string TrimTrailingDirectorySeparators(string path)
    {
        var root = Path.GetPathRoot(path) ?? string.Empty;
        while (path.Length > root.Length &&
               (path[^1] == Path.DirectorySeparatorChar || path[^1] == Path.AltDirectorySeparatorChar))
        {
            path = path[..^1];
        }

        return path;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static void ParseSingleRequire(
        string manifestPath,
        string line,
        DependencyInventoryState state,
        List<(string ModulePath, string Version)> directPseudoVersions,
        bool suppressManifestHygieneFindings)
    {
        // Format: module/path [version]
        // or: module/path v1.2.3
        // or: module/path v1.2.3 // indirect
        var trimmed = line.TrimEnd(')');

        var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 1)
        {
            return;
        }

        var modulePath = parts[0];
        var version = parts.Length > 1 ? parts[1] : null;
        var isIndirect = trimmed.Contains("// indirect", StringComparison.OrdinalIgnoreCase);

        // Skip Go toolchain and go directive lines
        if (modulePath is "go" or "toolchain")
        {
            return;
        }

        var isPinned = version != null && ExactGoVersionPattern().IsMatch(version);
        var isPseudoVersion = version != null && IsPseudoVersion(version);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (isIndirect)
        {
            metadata["directness"] = "indirect";
        }

        if (isPseudoVersion)
        {
            metadata["pseudoVersion"] = "true";
        }

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Go,
            modulePath,
            version,
            DependencyScope.Unknown,
            manifestPath,
            null, // go.sum is not per-package
            !isIndirect,
            isPinned,
            false,
            metadata.Count > 0 ? metadata : null));

        if (!isPinned && version != null && !suppressManifestHygieneFindings)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP024",
                "Go dependency uses a non-exact version",
                Severity.Medium,
                Confidence.High,
                $"Go dependency '{modulePath}' does not use an exact pinned version.",
                "go-require",
                $"Module '{modulePath}' has version '{version}'.",
                manifestPath,
                "Use exact versions with a committed go.sum for reproducible Go builds."));
        }

        if (isPseudoVersion && !isIndirect && version is not null && !suppressManifestHygieneFindings)
        {
            directPseudoVersions.Add((modulePath, version));
        }
    }

    private static void AddReplaceDirectiveFinding(
        string manifestPath,
        IReadOnlyList<string> replaceDirectives,
        DependencyInventoryState state)
    {
        if (replaceDirectives.Count == 0)
        {
            return;
        }

        var sample = string.Join("; ", replaceDirectives.Take(3));
        state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
            "TRUST-DEP023",
            "Go module uses replace directive",
            Severity.Low,
            Confidence.High,
            replaceDirectives.Count == 1
                ? "The go.mod file contains a replace directive."
                : $"The go.mod file contains {replaceDirectives.Count} replace directives.",
            "go-replace-directive",
            replaceDirectives.Count == 1 ? sample : $"First replace directives: {sample}",
            manifestPath,
            "Review replace directives because they override resolved module versions."));
    }

    private static void AddPseudoVersionFinding(
        string manifestPath,
        IReadOnlyList<(string ModulePath, string Version)> directPseudoVersions,
        DependencyInventoryState state)
    {
        if (directPseudoVersions.Count == 0)
        {
            return;
        }

        var sample = string.Join(
            "; ",
            directPseudoVersions
                .Take(3)
                .Select(dependency => $"{dependency.ModulePath}@{dependency.Version}"));
        state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
            "TRUST-DEP025",
            "Direct Go dependency uses a pseudo-version",
            Severity.Low,
            Confidence.High,
            directPseudoVersions.Count == 1
                ? $"Go dependency '{directPseudoVersions[0].ModulePath}' references a pseudo-version."
                : $"go.mod contains {directPseudoVersions.Count} direct dependencies that reference pseudo-versions.",
            "go-pseudo-version",
            directPseudoVersions.Count == 1 ? sample : $"First pseudo-version dependencies: {sample}",
            manifestPath,
            "Prefer tagged releases over pseudo-versions and review pseudo-version origins."));
    }

    private static bool IsPseudoVersion(string version) =>
        PseudoVersionPattern().IsMatch(version);

    private static bool ModuleLooksPseudoVersion(string modulePath, string[] lines) =>
        lines.Any(line => line.TrimStart().StartsWith("require ", StringComparison.Ordinal) &&
                          PseudoVersionPattern().IsMatch(line));

    [GeneratedRegex(@"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactGoVersionPattern();

    [GeneratedRegex(@"^v\d+\.\d+\.\d+-[0-9]{14}-[0-9a-f]{12}", RegexOptions.CultureInvariant)]
    private static partial Regex PseudoVersionPattern();

    private sealed record GoReplaceDirective(string ModulePath, string Target);
}

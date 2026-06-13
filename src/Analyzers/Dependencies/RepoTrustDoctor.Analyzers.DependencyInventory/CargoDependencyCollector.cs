using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class CargoDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Cargo.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        var lockfiles = LockfileNames
            .SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name))
            .ToArray();
        var workspaceLockRoots = lockfiles
            .Select(Path.GetDirectoryName)
            .Where(directory => !string.IsNullOrWhiteSpace(directory))
            .Select(directory => directory!)
            .Where(IsCargoWorkspaceRoot)
            .ToArray();

        foreach (var lockfile in lockfiles)
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Cargo,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var cargoToml in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Cargo.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeCargoToml(context, cargoToml, workspaceLockRoots, state);
        }
    }

    private void AnalyzeCargoToml(
        AnalysisContext context,
        string filePath,
        IReadOnlyCollection<string> workspaceLockRoots,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Cargo, relativePath, "Cargo.toml"));

        var hasCargoLock = HasCargoLock(filePath, workspaceLockRoots);
        if (!hasCargoLock)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP026",
                "Cargo project does not have a Cargo.lock file",
                Severity.Medium,
                Confidence.High,
                "A Cargo.toml file exists but no Cargo.lock was found alongside it.",
                "package-manifest",
                "No Cargo.lock file was found alongside Cargo.toml.",
                relativePath,
                "Commit Cargo.lock to the repository for reproducible builds (recommended for binaries)."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        CargoSection currentSection = CargoSection.None;
        CargoTableDependency? tableDependency = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                FlushCargoTableDependency(ref tableDependency, context.RepositoryPath, relativePath, hasCargoLock, state);

                if (TryParseCargoDependencyTable(line, out var tableCrateName, out var tableScope))
                {
                    tableDependency = new CargoTableDependency(tableCrateName, tableScope);
                    currentSection = CargoSection.None;
                    continue;
                }

                currentSection = ParseCargoSection(line);
                continue;
            }

            if (tableDependency is not null)
            {
                ParseCargoDependencyTableLine(line, tableDependency);
                continue;
            }

            if (!IsDependencySection(currentSection))
            {
                continue;
            }

            var scope = MapCargoSectionToScope(currentSection);

            // Parse line like: crate_name = "1.2.3"
            // or: crate_name = { version = "1.2.3", features = [...] }
            // or: crate_name = { git = "https://...", branch = "main" }
            // or: crate_name = { path = "../local" }
            var equalsIndex = line.IndexOf('=', StringComparison.Ordinal);
            if (equalsIndex < 0)
            {
                continue;
            }

            var crateName = line[..equalsIndex].Trim();
            var valuePart = line[(equalsIndex + 1)..].Trim();

            if (string.IsNullOrWhiteSpace(crateName) || string.IsNullOrWhiteSpace(valuePart))
            {
                continue;
            }

            if (IsCargoDependencyMetadataKey(crateName))
            {
                continue;
            }

            if (valuePart.StartsWith('{'))
            {
                ParseCargoInlineTable(context.RepositoryPath, relativePath, crateName, valuePart, scope, hasCargoLock, state);
            }
            else
            {
                ParseCargoSimpleVersion(relativePath, crateName, valuePart.Trim('"'), scope, hasCargoLock, state);
            }
        }

        FlushCargoTableDependency(ref tableDependency, context.RepositoryPath, relativePath, hasCargoLock, state);
    }

    private static bool HasCargoLock(string cargoTomlPath, IReadOnlyCollection<string> workspaceLockRoots)
    {
        var directory = Path.GetDirectoryName(cargoTomlPath);
        if (directory == null)
        {
            return false;
        }

        var cargoLockPath = Path.Combine(directory, "Cargo.lock");
        if (File.Exists(cargoLockPath))
        {
            return true;
        }

        return workspaceLockRoots.Any(root => IsSameOrChildPath(directory, root));
    }

    private static CargoSection ParseCargoSection(string line)
    {
        var section = line.Trim('[', ']').Trim();

        if (section.StartsWith("workspace.", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.WorkspaceDependencies;
        }

        if (section.Equals("build-dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".build-dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.BuildDependencies;
        }

        if (section.Equals("dev-dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".dev-dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.DevDependencies;
        }

        if (section.Equals("dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.Dependencies;
        }

        return CargoSection.None;
    }

    private static bool TryParseCargoDependencyTable(string line, out string crateName, out DependencyScope scope)
    {
        var section = line.Trim('[', ']').Trim();
        crateName = string.Empty;
        scope = DependencyScope.Production;

        if (section.StartsWith("workspace.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (TryReadDependencyTableName(section, "build-dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".build-dependencies.", out crateName))
        {
            scope = DependencyScope.Development;
            return true;
        }

        if (TryReadDependencyTableName(section, "dev-dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".dev-dependencies.", out crateName))
        {
            scope = DependencyScope.Development;
            return true;
        }

        if (TryReadDependencyTableName(section, "dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".dependencies.", out crateName))
        {
            scope = DependencyScope.Production;
            return true;
        }

        return false;
    }

    private static bool TryReadDependencyTableName(string section, string marker, out string crateName)
    {
        crateName = string.Empty;
        var markerIndex = section.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0)
        {
            return false;
        }

        crateName = section[(markerIndex + marker.Length)..].Trim().Trim('"', '\'');
        return crateName.Length > 0 && !crateName.Contains('.', StringComparison.Ordinal);
    }

    private static bool IsDependencySection(CargoSection section) =>
        section is CargoSection.Dependencies or CargoSection.DevDependencies or CargoSection.BuildDependencies;

    private static DependencyScope MapCargoSectionToScope(CargoSection section) =>
        section switch
        {
            CargoSection.DevDependencies => DependencyScope.Development,
            CargoSection.BuildDependencies => DependencyScope.Development,
            _ => DependencyScope.Production
        };

    private void ParseCargoInlineTable(
        string repositoryPath,
        string manifestPath,
        string crateName,
        string valuePart,
        DependencyScope scope,
        bool hasCargoLock,
        DependencyInventoryState state)
    {
        // Extract version from inline table like { version = "1.2.3", features = [...] }
        var version = ExtractCargoInlineValue(valuePart, "version");
        var isGit = valuePart.Contains("git", StringComparison.OrdinalIgnoreCase) &&
                    ExtractCargoInlineValue(valuePart, "git") != null;
        var pathSource = valuePart.Contains("path", StringComparison.OrdinalIgnoreCase)
            ? ExtractCargoInlineValue(valuePart, "path")
            : null;
        var isPath = pathSource != null;
        var isRepositoryLocalPath = IsRepositoryLocalPathDependency(repositoryPath, manifestPath, pathSource);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (isGit)
        {
            metadata["sourceKind"] = "git";
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP027",
                "Cargo dependency uses a Git source",
                Severity.Medium,
                Confidence.High,
                $"Cargo dependency '{crateName}' references a Git source instead of a registry version.",
                "cargo-git-dependency",
                $"Crate '{crateName}' uses a Git source.",
                manifestPath,
                "Review Git-sourced dependencies and prefer crates.io packages with pinned versions when possible."));
        }

        if (isPath)
        {
            metadata["sourceKind"] = "path";
            if (!isRepositoryLocalPath)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP028",
                    "Cargo dependency uses a path source",
                    Severity.Low,
                    Confidence.High,
                    $"Cargo dependency '{crateName}' references a path outside the repository instead of a registry version.",
                    "cargo-path-dependency",
                    $"Crate '{crateName}' uses path source '{pathSource}'.",
                    manifestPath,
                    "Review path-sourced dependencies because they can bypass registry provenance and may depend on local filesystem state."));
            }
        }

        var isPinned = IsExactCargoRequirement(version);
        var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(version);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Cargo,
            crateName,
            version,
            scope,
            manifestPath,
            null,
            true,
            isPinned,
            isPrerelease,
            metadata.Count > 0 ? metadata : null));

        if (!isPinned && version != null && !hasCargoLock)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP029",
                "Cargo dependency uses a non-exact version without lockfile",
                Severity.Medium,
                Confidence.High,
                $"Cargo dependency '{crateName}' does not use an exact pinned version and no Cargo.lock was found.",
                "cargo-dependency",
                $"Crate '{crateName}' has version '{version}'.",
                manifestPath,
                "Commit Cargo.lock for reproducible Cargo builds, or use exact versions when strict direct dependency pinning is required."));
        }

        if (isPrerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP030",
                "Cargo dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"Cargo dependency '{crateName}' uses a prerelease version.",
                "cargo-prerelease",
                $"Crate '{crateName}' has prerelease version '{version}'.",
                manifestPath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private void ParseCargoDependencyTableLine(string line, CargoTableDependency tableDependency)
    {
        var equalsIndex = line.IndexOf('=', StringComparison.Ordinal);
        if (equalsIndex < 0)
        {
            return;
        }

        var key = line[..equalsIndex].Trim();
        var value = line[(equalsIndex + 1)..].Trim().Trim('"');

        if (key.Equals("version", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Version = value;
        }
        else if (key.Equals("git", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Git = value;
        }
        else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Path = value;
        }
    }

    private void FlushCargoTableDependency(
        ref CargoTableDependency? tableDependency,
        string repositoryPath,
        string manifestPath,
        bool hasCargoLock,
        DependencyInventoryState state)
    {
        if (tableDependency is null)
        {
            return;
        }

        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(tableDependency.Version))
        {
            parts.Add($"version = \"{tableDependency.Version}\"");
        }
        if (!string.IsNullOrWhiteSpace(tableDependency.Git))
        {
            parts.Add($"git = \"{tableDependency.Git}\"");
        }
        if (!string.IsNullOrWhiteSpace(tableDependency.Path))
        {
            parts.Add($"path = \"{tableDependency.Path}\"");
        }

        ParseCargoInlineTable(
            repositoryPath,
            manifestPath,
            tableDependency.CrateName,
            "{ " + string.Join(", ", parts) + " }",
            tableDependency.Scope,
            hasCargoLock,
            state);
        tableDependency = null;
    }

    private void ParseCargoSimpleVersion(string manifestPath, string crateName, string version, DependencyScope scope, bool hasCargoLock, DependencyInventoryState state)
    {
        var isPinned = IsExactCargoRequirement(version);
        var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(version);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Cargo,
            crateName,
            version,
            scope,
            manifestPath,
            null,
            true,
            isPinned,
            isPrerelease,
            null));

        if (!isPinned && !hasCargoLock)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP029",
                "Cargo dependency uses a non-exact version without lockfile",
                Severity.Medium,
                Confidence.High,
                $"Cargo dependency '{crateName}' does not use an exact pinned version and no Cargo.lock was found.",
                "cargo-dependency",
                $"Crate '{crateName}' has version '{version}'.",
                manifestPath,
                "Commit Cargo.lock for reproducible Cargo builds, or use exact versions when strict direct dependency pinning is required."));
        }

        if (isPrerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP030",
                "Cargo dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"Cargo dependency '{crateName}' uses a prerelease version.",
                "cargo-prerelease",
                $"Crate '{crateName}' has prerelease version '{version}'.",
                manifestPath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private static string? ExtractCargoInlineValue(string inlineTable, string key)
    {
        // Simple extraction: find key = "value" inside { ... }
        var pattern = $@"\b{Regex.Escape(key)}\s*=\s*""([^""]*)""";
        var match = Regex.Match(inlineTable, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static bool IsCargoDependencyMetadataKey(string crateName) =>
        crateName.Equals("version", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("features", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("default-features", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("optional", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("path", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("git", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("branch", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("tag", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("rev", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("registry", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("package", StringComparison.OrdinalIgnoreCase);

    private static bool IsExactCargoRequirement(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        version.StartsWith('=') &&
        ExactCargoVersionPattern().IsMatch(version[1..].Trim());

    private static bool IsCargoWorkspaceRoot(string directory)
    {
        var manifestPath = Path.Combine(directory, "Cargo.toml");
        if (!RepositoryFileSystem.CanReadAsText(manifestPath))
        {
            return false;
        }

        try
        {
            return File.ReadAllText(manifestPath).Contains("[workspace]", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsRepositoryLocalPathDependency(string repositoryPath, string manifestPath, string? dependencyPath)
    {
        if (string.IsNullOrWhiteSpace(dependencyPath))
        {
            return false;
        }

        var normalizedManifestPath = manifestPath.Replace('/', Path.DirectorySeparatorChar);
        var manifestDirectory = Path.GetDirectoryName(Path.Combine(repositoryPath, normalizedManifestPath));
        if (manifestDirectory is null)
        {
            return false;
        }

        var fullDependencyPath = Path.GetFullPath(Path.IsPathRooted(dependencyPath)
            ? dependencyPath
            : Path.Combine(manifestDirectory, dependencyPath));
        return IsSameOrChildPath(fullDependencyPath, Path.GetFullPath(repositoryPath));
    }

    private static bool IsSameOrChildPath(string path, string parent)
    {
        var normalizedPath = TrimTrailingDirectorySeparators(Path.GetFullPath(path));
        var normalizedParent = TrimTrailingDirectorySeparators(Path.GetFullPath(parent));
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

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactCargoVersionPattern();
}

internal sealed class CargoTableDependency(string crateName, DependencyScope scope)
{
    public string CrateName { get; } = crateName;

    public DependencyScope Scope { get; } = scope;

    public string? Version { get; set; }

    public string? Git { get; set; }

    public string? Path { get; set; }
}

internal enum CargoSection
{
    None,
    Dependencies,
    DevDependencies,
    BuildDependencies,
    WorkspaceDependencies
}

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
            .Where(CargoDependencyParsing.IsWorkspaceRoot)
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

        var cargoLockPath = FindCargoLock(filePath, workspaceLockRoots);
        var hasCargoLock = cargoLockPath is not null;
        var lockfile = cargoLockPath is not null
            ? CargoLockfileResolver.TryCreate(
                cargoLockPath,
                DependencyInventorySupport.Relative(context, cargoLockPath),
                state)
            : null;
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
                FlushCargoTableDependency(ref tableDependency, context.RepositoryPath, relativePath, hasCargoLock, lockfile, state);

                if (CargoDependencyParsing.TryParseDependencyTable(line, out var tableCrateName, out var tableScope))
                {
                    tableDependency = new CargoTableDependency(tableCrateName, tableScope);
                    currentSection = CargoSection.None;
                    continue;
                }

                currentSection = CargoDependencyParsing.ParseSection(line);
                continue;
            }

            if (tableDependency is not null)
            {
                CargoDependencyParsing.ParseDependencyTableLine(line, tableDependency);
                continue;
            }

            if (!CargoDependencyParsing.IsDependencySection(currentSection))
            {
                continue;
            }

            var scope = CargoDependencyParsing.MapSectionToScope(currentSection);

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

            if (CargoDependencyParsing.IsDependencyMetadataKey(crateName))
            {
                continue;
            }

            if (valuePart.StartsWith('{'))
            {
                ParseCargoInlineTable(context.RepositoryPath, relativePath, crateName, valuePart, scope, hasCargoLock, lockfile, state);
            }
            else
            {
                ParseCargoSimpleVersion(relativePath, crateName, valuePart.Trim('"'), scope, hasCargoLock, lockfile, state);
            }
        }

        FlushCargoTableDependency(ref tableDependency, context.RepositoryPath, relativePath, hasCargoLock, lockfile, state);
    }

    private static string? FindCargoLock(
        string cargoTomlPath,
        IReadOnlyCollection<string> workspaceLockRoots)
    {
        var directory = Path.GetDirectoryName(cargoTomlPath);
        if (directory == null)
        {
            return null;
        }

        var cargoLockPath = Path.Combine(directory, "Cargo.lock");
        if (File.Exists(cargoLockPath))
        {
            return cargoLockPath;
        }

        var workspaceRoot = workspaceLockRoots
            .Where(root => CargoDependencyParsing.IsSameOrChildPath(directory, root))
            .OrderByDescending(root => root.Length)
            .FirstOrDefault();
        return workspaceRoot is null ? null : Path.Combine(workspaceRoot, "Cargo.lock");
    }

    private void ParseCargoInlineTable(
        string repositoryPath,
        string manifestPath,
        string crateName,
        string valuePart,
        DependencyScope scope,
        bool hasCargoLock,
        CargoLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        // Extract version from inline table like { version = "1.2.3", features = [...] }
        var version = CargoDependencyParsing.ExtractInlineValue(valuePart, "version");
        var isGit = valuePart.Contains("git", StringComparison.OrdinalIgnoreCase) &&
                    CargoDependencyParsing.ExtractInlineValue(valuePart, "git") != null;
        var pathSource = valuePart.Contains("path", StringComparison.OrdinalIgnoreCase)
            ? CargoDependencyParsing.ExtractInlineValue(valuePart, "path")
            : null;
        var isPath = pathSource != null;
        var isRepositoryLocalPath = CargoDependencyParsing.IsRepositoryLocalPathDependency(repositoryPath, manifestPath, pathSource);
        var packageName = CargoDependencyParsing.ExtractInlineValue(valuePart, "package") ?? crateName;
        var resolvedVersion = string.Empty;
        var resolved = !isGit &&
                       !isPath &&
                       lockfile is not null &&
                       lockfile.TryResolve(packageName, out resolvedVersion);
        var effectiveVersion = resolved ? resolvedVersion : version;

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!packageName.Equals(crateName, StringComparison.OrdinalIgnoreCase))
        {
            metadata["manifestAlias"] = crateName;
        }
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
        if (resolved)
        {
            metadata["requestedVersion"] = version ?? string.Empty;
            metadata["versionSource"] = "Cargo.lock";
        }

        var isPinned = resolved || CargoDependencyParsing.IsExactRequirement(version);
        var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Cargo,
            packageName,
            effectiveVersion,
            scope,
            manifestPath,
            resolved ? lockfile!.RelativePath : null,
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

    private void FlushCargoTableDependency(
        ref CargoTableDependency? tableDependency,
        string repositoryPath,
        string manifestPath,
        bool hasCargoLock,
        CargoLockfileResolver? lockfile,
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
        if (!string.IsNullOrWhiteSpace(tableDependency.Package))
        {
            parts.Add($"package = \"{tableDependency.Package}\"");
        }

        ParseCargoInlineTable(
            repositoryPath,
            manifestPath,
            tableDependency.CrateName,
            "{ " + string.Join(", ", parts) + " }",
            tableDependency.Scope,
            hasCargoLock,
            lockfile,
            state);
        tableDependency = null;
    }

    private void ParseCargoSimpleVersion(
        string manifestPath,
        string crateName,
        string version,
        DependencyScope scope,
        bool hasCargoLock,
        CargoLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        var resolvedVersion = string.Empty;
        var resolved = lockfile is not null &&
                       lockfile.TryResolve(crateName, out resolvedVersion);
        var effectiveVersion = resolved ? resolvedVersion : version;
        var isPinned = resolved || CargoDependencyParsing.IsExactRequirement(version);
        var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);
        IReadOnlyDictionary<string, string>? metadata = resolved
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["requestedVersion"] = version,
                ["versionSource"] = "Cargo.lock"
            }
            : null;

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Cargo,
            crateName,
            effectiveVersion,
            scope,
            manifestPath,
            resolved ? lockfile!.RelativePath : null,
            true,
            isPinned,
            isPrerelease,
            metadata));

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

}

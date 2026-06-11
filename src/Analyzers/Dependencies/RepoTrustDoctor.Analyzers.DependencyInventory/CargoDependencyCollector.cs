using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class CargoDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Cargo.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Cargo,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var cargoToml in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Cargo.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeCargoToml(context, cargoToml, state);
        }
    }

    private void AnalyzeCargoToml(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Cargo, relativePath, "Cargo.toml"));

        var hasCargoLock = HasCargoLock(context, filePath);
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

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = ParseCargoSection(line);
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

            if (valuePart.StartsWith('{'))
            {
                ParseCargoInlineTable(relativePath, crateName, valuePart, scope, state);
            }
            else
            {
                ParseCargoSimpleVersion(relativePath, crateName, valuePart.Trim('"'), scope, state);
            }
        }
    }

    private static bool HasCargoLock(AnalysisContext context, string cargoTomlPath)
    {
        var directory = Path.GetDirectoryName(cargoTomlPath);
        if (directory == null)
        {
            return false;
        }

        var cargoLockPath = Path.Combine(directory, "Cargo.lock");
        return File.Exists(cargoLockPath);
    }

    private static CargoSection ParseCargoSection(string line)
    {
        if (line.Contains("dependencies", StringComparison.OrdinalIgnoreCase))
        {
            if (line.Contains("build", StringComparison.OrdinalIgnoreCase))
            {
                return CargoSection.BuildDependencies;
            }
            if (line.Contains("dev", StringComparison.OrdinalIgnoreCase))
            {
                return CargoSection.DevDependencies;
            }
            // workspace.dependencies should be treated as a reference, not direct
            if (line.Contains("workspace", StringComparison.OrdinalIgnoreCase))
            {
                return CargoSection.WorkspaceDependencies;
            }
            return CargoSection.Dependencies;
        }

        return CargoSection.None;
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

    private void ParseCargoInlineTable(string manifestPath, string crateName, string valuePart, DependencyScope scope, DependencyInventoryState state)
    {
        // Extract version from inline table like { version = "1.2.3", features = [...] }
        var version = ExtractCargoInlineValue(valuePart, "version");
        var isGit = valuePart.Contains("git", StringComparison.OrdinalIgnoreCase) &&
                    ExtractCargoInlineValue(valuePart, "git") != null;
        var isPath = valuePart.Contains("path", StringComparison.OrdinalIgnoreCase) &&
                     ExtractCargoInlineValue(valuePart, "path") != null;

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
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP028",
                "Cargo dependency uses a path source",
                Severity.Low,
                Confidence.High,
                $"Cargo dependency '{crateName}' references a local path instead of a registry version.",
                "cargo-path-dependency",
                $"Crate '{crateName}' uses a path source.",
                manifestPath,
                "Review path-sourced dependencies because they depend on repository layout and may bypass registry provenance."));
        }

        var isPinned = version != null && ExactCargoVersionPattern().IsMatch(version);
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

        if (!isPinned && version != null)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP029",
                "Cargo dependency uses a non-exact version",
                Severity.Medium,
                Confidence.High,
                $"Cargo dependency '{crateName}' does not use an exact pinned version.",
                "cargo-dependency",
                $"Crate '{crateName}' has version '{version}'.",
                manifestPath,
                "Use exact versions with a committed Cargo.lock for reproducible Cargo builds."));
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

    private void ParseCargoSimpleVersion(string manifestPath, string crateName, string version, DependencyScope scope, DependencyInventoryState state)
    {
        var isPinned = ExactCargoVersionPattern().IsMatch(version);
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

        if (!isPinned)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP029",
                "Cargo dependency uses a non-exact version",
                Severity.Medium,
                Confidence.High,
                $"Cargo dependency '{crateName}' does not use an exact pinned version.",
                "cargo-dependency",
                $"Crate '{crateName}' has version '{version}'.",
                manifestPath,
                "Use exact versions with a committed Cargo.lock for reproducible Cargo builds."));
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

    [GeneratedRegex(@"^\d+\.\d+\.\d+$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactCargoVersionPattern();
}

internal enum CargoSection
{
    None,
    Dependencies,
    DevDependencies,
    BuildDependencies,
    WorkspaceDependencies
}

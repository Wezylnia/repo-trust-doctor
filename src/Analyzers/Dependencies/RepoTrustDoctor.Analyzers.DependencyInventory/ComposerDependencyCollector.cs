using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class ComposerDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["composer.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Composer,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var composerJson in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "composer.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeComposerJson(context, composerJson, state);
        }
    }

    private static void AnalyzeComposerJson(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Composer, relativePath, "composer.json"));

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            });

            var root = document.RootElement;
            var hasComposerLock = HasComposerLock(filePath);
            var lockfile = hasComposerLock
                ? CreateLockfileResolver(context, filePath, state)
                : null;
            var isApplicationManifest = IsApplicationManifest(relativePath, root);
            if (isApplicationManifest && !hasComposerLock)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP031",
                    "Composer application does not have a composer.lock file",
                    Severity.Medium,
                    Confidence.High,
                    "A Composer application manifest exists but no composer.lock was found alongside it.",
                    "package-manifest",
                    "No composer.lock file was found alongside the application composer.json.",
                    relativePath,
                    "Run 'composer install' and commit composer.lock to the repository for reproducible application builds."));
            }

            var nonExactConstraints = new List<ComposerConstraint>();
            ParseDependencySection(root, "require", relativePath, DependencyScope.Production, lockfile, state, nonExactConstraints);
            ParseDependencySection(root, "require-dev", relativePath, DependencyScope.Development, lockfile, state, nonExactConstraints);

            if (isApplicationManifest && !hasComposerLock && nonExactConstraints.Count > 0)
            {
                AddAggregatedNonExactFinding(relativePath, nonExactConstraints, state);
            }
        }
        catch (JsonException ex)
        {
            state.Warnings.Add($"Could not parse composer.json '{relativePath}': {ex.Message}");
        }
    }

    private static void ParseDependencySection(
        System.Text.Json.JsonElement root,
        string sectionName,
        string manifestPath,
        DependencyScope scope,
        ComposerLockfileResolver? lockfile,
        DependencyInventoryState state,
        List<ComposerConstraint> nonExactConstraints)
    {
        if (!root.TryGetProperty(sectionName, out var section) || section.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var property in section.EnumerateObject())
        {
            var packageName = property.Name;
            var versionConstraint = property.Value.GetString();

            if (string.IsNullOrWhiteSpace(packageName) || string.IsNullOrWhiteSpace(versionConstraint))
            {
                continue;
            }

            if (IsComposerPlatformRequirement(packageName))
            {
                continue;
            }

            var resolvedVersion = string.Empty;
            var resolved = lockfile is not null &&
                           lockfile.TryResolve(packageName, out resolvedVersion);
            var effectiveVersion = resolved ? resolvedVersion : versionConstraint;
            var isPinned = resolved || IsExactVersion(versionConstraint);
            var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);
            IReadOnlyDictionary<string, string>? metadata = resolved
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["requestedVersion"] = versionConstraint,
                    ["versionSource"] = "composer.lock"
                }
                : null;

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Composer,
                packageName,
                effectiveVersion,
                scope,
                manifestPath,
                resolved ? lockfile!.RelativePath : null,
                true,
                isPinned,
                isPrerelease,
                metadata));

            if (!isPinned)
            {
                nonExactConstraints.Add(new ComposerConstraint(packageName, versionConstraint));
            }

            if (isPrerelease)
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP033",
                    "Composer dependency uses a prerelease version",
                    Severity.Low,
                    Confidence.High,
                    $"Composer dependency '{packageName}' uses a prerelease version.",
                    "composer-prerelease",
                    $"Package '{packageName}' has prerelease version '{versionConstraint}'.",
                    manifestPath,
                    "Review whether the prerelease dependency is intentional before production use."));
            }
        }
    }

    private static void AddAggregatedNonExactFinding(
        string manifestPath,
        IReadOnlyList<ComposerConstraint> nonExactConstraints,
        DependencyInventoryState state)
    {
        var samples = nonExactConstraints
            .Take(5)
            .Select(constraint => $"{constraint.PackageName} ({constraint.VersionConstraint})")
            .ToArray();
        var suffix = nonExactConstraints.Count > samples.Length
            ? $" and {nonExactConstraints.Count - samples.Length} more"
            : string.Empty;
        var sampleText = string.Join(", ", samples) + suffix;

        state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
            "TRUST-DEP032",
            "Composer application has unlocked version constraints",
            Severity.Medium,
            Confidence.High,
            $"Composer application manifest has {nonExactConstraints.Count} non-exact dependency constraints without a lockfile.",
            "composer-require",
            $"Non-exact constraints without composer.lock: {sampleText}.",
            manifestPath,
            "Commit composer.lock for applications; reusable Composer libraries can intentionally publish version ranges without a lockfile."));
    }

    private static bool HasComposerLock(string composerJsonPath)
    {
        var directory = Path.GetDirectoryName(composerJsonPath);
        if (directory == null)
        {
            return false;
        }

        var composerLockPath = Path.Combine(directory, "composer.lock");
        return File.Exists(composerLockPath);
    }

    private static ComposerLockfileResolver? CreateLockfileResolver(
        AnalysisContext context,
        string composerJsonPath,
        DependencyInventoryState state)
    {
        var lockfilePath = Path.Combine(Path.GetDirectoryName(composerJsonPath)!, "composer.lock");
        return ComposerLockfileResolver.TryCreate(
            lockfilePath,
            DependencyInventorySupport.Relative(context, lockfilePath),
            state);
    }

    private static bool IsApplicationManifest(string relativePath, JsonElement root)
    {
        if (!relativePath.Equals("composer.json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (TryGetString(root, "type", out var type))
        {
            return type.Equals("project", StringComparison.OrdinalIgnoreCase);
        }

        if (TryGetString(root, "name", out var name) && name.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    private static bool TryGetString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool IsComposerPlatformRequirement(string packageName) =>
        packageName.Equals("php", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("composer-runtime-api", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("composer-plugin-api", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("ext-", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("lib-", StringComparison.OrdinalIgnoreCase);

    private static bool IsExactVersion(string versionConstraint)
    {
        // Exact versions look like "1.2.3" with no operators, wildcards, or ranges
        return versionConstraint.Length > 0 &&
               !versionConstraint.Contains(' ', StringComparison.Ordinal) &&
               !versionConstraint.StartsWith('^') &&
               !versionConstraint.StartsWith('~') &&
               !versionConstraint.StartsWith('>') &&
               !versionConstraint.StartsWith('<') &&
               !versionConstraint.StartsWith('!') &&
               !versionConstraint.Contains('*') &&
               !versionConstraint.Contains("||", StringComparison.Ordinal) &&
               char.IsDigit(versionConstraint[0]);
    }

    private sealed record ComposerConstraint(string PackageName, string VersionConstraint);
}

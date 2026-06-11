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

        var hasComposerLock = HasComposerLock(context, filePath);
        if (!hasComposerLock)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP031",
                "Composer project does not have a composer.lock file",
                Severity.Medium,
                Confidence.High,
                "A composer.json file exists but no composer.lock was found alongside it.",
                "package-manifest",
                "No composer.lock file was found alongside composer.json.",
                relativePath,
                "Run 'composer install' and commit composer.lock to the repository for reproducible builds."));
        }

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

            ParseDependencySection(root, "require", relativePath, DependencyScope.Production, state);
            ParseDependencySection(root, "require-dev", relativePath, DependencyScope.Development, state);
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
        DependencyInventoryState state)
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

            // Skip php version constraint
            if (packageName.Equals("php", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var isPinned = IsExactVersion(versionConstraint);
            var isPrerelease = DependencyInventorySupport.IsPrereleaseVersion(versionConstraint);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Composer,
                packageName,
                versionConstraint,
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
                    "TRUST-DEP032",
                    "Composer dependency uses a non-exact version constraint",
                    Severity.Medium,
                    Confidence.High,
                    $"Composer dependency '{packageName}' uses a version constraint '{versionConstraint}' instead of an exact version.",
                    "composer-require",
                    $"Package '{packageName}' has version constraint '{versionConstraint}'.",
                    manifestPath,
                    "Use exact version constraints or commit composer.lock for reproducible installs."));
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

    private static bool HasComposerLock(AnalysisContext context, string composerJsonPath)
    {
        var directory = Path.GetDirectoryName(composerJsonPath);
        if (directory == null)
        {
            return false;
        }

        var composerLockPath = Path.Combine(directory, "composer.lock");
        return File.Exists(composerLockPath);
    }

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
}

using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class NpmDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var manifest in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeManifest(context, state, manifest);
        }
    }

    private static void AnalyzeManifest(AnalysisContext context, DependencyInventoryState state, string manifest)
    {
        var relativePath = DependencyInventorySupport.Relative(context, manifest);
        var directory = Path.GetDirectoryName(manifest);
        if (directory is null)
        {
            return;
        }

        var coveringLockfiles = FindCoveringLockfiles(context.RepositoryPath, directory);

        foreach (var lockfile in coveringLockfiles)
        {
            AddLockfile(context, state, lockfile);
        }

        if (coveringLockfiles.Length == 0)
        {
            state.Findings.Add(new Finding(
                "TRUST-DEP001",
                "npm manifest exists without lockfile",
                AnalysisCategory.Dependencies,
                Severity.Medium,
                Confidence.High,
                "npm manifest exists without lockfile",
                [new Evidence("package-manifest", "A package.json file exists but no lockfile was found.", relativePath)],
                new Recommendation("Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository.")));
        }

        if (!DependencyInventorySupport.TryReadText(manifest, out var json, state.Warnings, relativePath))
        {
            state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Npm, relativePath, "package.json"));
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            state.Manifests.Add(new DependencyManifestInfo(
                DependencyEcosystem.Npm,
                relativePath,
                "package.json",
                ReadManifestMetadata(root)));

            ReadDependencySection(root, "dependencies", DependencyScope.Production, relativePath, coveringLockfiles, context, state);
            ReadDependencySection(root, "devDependencies", DependencyScope.Development, relativePath, coveringLockfiles, context, state);
            ReadDependencySection(root, "optionalDependencies", DependencyScope.Optional, relativePath, coveringLockfiles, context, state);
            ReadDependencySection(root, "peerDependencies", DependencyScope.Peer, relativePath, coveringLockfiles, context, state);
            AddInstallScriptFindings(root, relativePath, state);
        }
        catch (JsonException ex)
        {
            state.Warnings.Add($"Could not parse npm manifest '{relativePath}': {ex.Message}");
            state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Npm, relativePath, "package.json"));
        }
    }

    private static void ReadDependencySection(
        JsonElement root,
        string sectionName,
        DependencyScope scope,
        string manifestPath,
        string[] coveringLockfiles,
        AnalysisContext context,
        DependencyInventoryState state)
    {
        if (!root.TryGetProperty(sectionName, out var section) || section.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var dependency in section.EnumerateObject())
        {
            var version = dependency.Value.ValueKind == JsonValueKind.String ? dependency.Value.GetString() : null;
            var normalizedVersion = DependencyInventorySupport.NormalizeVersion(version);
            var pinned = IsPinnedVersion(normalizedVersion);
            var prerelease = DependencyInventorySupport.IsPrereleaseVersion(normalizedVersion);
            var sourceKind = ClassifyVersionSpec(normalizedVersion);

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Npm,
                dependency.Name,
                normalizedVersion,
                scope,
                manifestPath,
                coveringLockfiles.Length == 0 ? null : DependencyInventorySupport.Relative(context, coveringLockfiles[0]),
                true,
                pinned,
                prerelease,
                new Dictionary<string, string>
                {
                    ["section"] = sectionName,
                    ["sourceKind"] = sourceKind.Kind
                }));

            AddVersionFindings(dependency.Name, sectionName, normalizedVersion, pinned, prerelease, sourceKind, manifestPath, coveringLockfiles.Length > 0, state);
        }
    }

    private static void AddVersionFindings(
        string name,
        string sectionName,
        string? version,
        bool pinned,
        bool prerelease,
        NpmSourceKind sourceKind,
        string manifestPath,
        bool hasCoveringLockfile,
        DependencyInventoryState state)
    {
        if (!pinned && !hasCoveringLockfile)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP006",
                "npm dependency uses a range or unpinned version",
                Severity.Medium,
                Confidence.High,
                $"npm dependency `{name}` uses a non-exact version.",
                "npm-package",
                $"Package `{name}` in `{sectionName}` uses version `{DependencyInventorySupport.DisplayVersion(version)}`.",
                manifestPath,
                "Use exact dependency versions together with a committed lockfile for reproducible installs."));
        }

        if (prerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP007",
                "npm dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"npm dependency `{name}` uses prerelease version `{version}`.",
                "npm-package",
                $"Package `{name}` in `{sectionName}` uses version `{version}`.",
                manifestPath,
                "Review prerelease dependencies and prefer stable versions where possible."));
        }

        if (sourceKind.IsRemote || sourceKind.IsLocal)
        {
            AddSourceFinding(name, sectionName, version, sourceKind, manifestPath, state);
        }
    }

    private static void AddSourceFinding(string name, string sectionName, string? version, NpmSourceKind sourceKind, string manifestPath, DependencyInventoryState state)
    {
        var remote = sourceKind.IsRemote;
        if (!remote && DependencyInventorySupport.IsLikelyExampleOrTestPath(manifestPath))
        {
            return;
        }

        state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
            remote ? "TRUST-DEP011" : "TRUST-DEP012",
            remote ? "npm dependency uses a direct remote source" : "npm dependency uses a local file source",
            remote ? Severity.Medium : Severity.Low,
            Confidence.High,
            remote ? $"npm dependency `{name}` points directly at a remote source." : $"npm dependency `{name}` points at a local source.",
            "npm-package",
            $"Package `{name}` in `{sectionName}` uses `{DependencyInventorySupport.DisplayVersion(version)}`.",
            manifestPath,
            remote
                ? "Review direct remote dependency sources and prefer registry packages with pinned versions when possible."
                : "Review local dependency sources because they depend on repository layout and may bypass registry provenance."));
    }

    private static void AddInstallScriptFindings(JsonElement root, string relativePath, DependencyInventoryState state)
    {
        if (!root.TryGetProperty("scripts", out var scripts) || scripts.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var scriptName in new[] { "preinstall", "install", "postinstall" })
        {
            if (scripts.TryGetProperty(scriptName, out var script) && script.ValueKind == JsonValueKind.String)
            {
                state.Findings.Add(new Finding(
                    "TRUST-DEP008",
                    "npm install-time script requires manual review",
                    AnalysisCategory.Dependencies,
                    Severity.Medium,
                    Confidence.Medium,
                    $"package.json defines `{scriptName}`. Install-time scripts can execute during dependency installation.",
                    [new Evidence("npm-script", $"Install-time script `{scriptName}` is defined.", relativePath, Value: scriptName)],
                    new Recommendation("Review install-time scripts and avoid downloading or executing untrusted remote code.")));
            }
        }
    }

    private static IReadOnlyDictionary<string, string> ReadManifestMetadata(JsonElement root)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("packageManager", out var packageManager) && packageManager.ValueKind == JsonValueKind.String)
        {
            metadata["packageManager"] = packageManager.GetString() ?? string.Empty;
        }

        if (root.TryGetProperty("engines", out var engines) && engines.ValueKind == JsonValueKind.Object)
        {
            foreach (var engine in engines.EnumerateObject())
            {
                if (engine.Value.ValueKind == JsonValueKind.String)
                {
                    metadata[$"engine.{engine.Name}"] = engine.Value.GetString() ?? string.Empty;
                }
            }
        }

        return metadata;
    }

    private static bool IsPinnedVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        DependencyInventorySupport.ExactSemVerPattern().IsMatch(version);

    private static NpmSourceKind ClassifyVersionSpec(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return new NpmSourceKind("registry", false, false);
        }

        var value = version.Trim();
        if (value.StartsWith("git+", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("git://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("github:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            value.Contains(".git#", StringComparison.OrdinalIgnoreCase))
        {
            return new NpmSourceKind("remote", true, false);
        }

        return value.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("link:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("portal:", StringComparison.OrdinalIgnoreCase)
            ? new NpmSourceKind("local", false, true)
            : value.StartsWith("workspace:", StringComparison.OrdinalIgnoreCase)
            ? new NpmSourceKind("workspace", false, false)
            : new NpmSourceKind("registry", false, false);
    }

    private static string[] FindCoveringLockfiles(string repositoryPath, string manifestDirectory)
    {
        var root = Path.GetFullPath(repositoryPath);
        var current = Path.GetFullPath(manifestDirectory);
        var results = new List<string>();

        while (current.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var lockfile in LockfileNames.Select(name => Path.Combine(current, name)).Where(File.Exists))
            {
                results.Add(lockfile);
            }

            if (string.Equals(current, root, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            var parent = Directory.GetParent(current);
            if (parent is null)
            {
                break;
            }

            current = parent.FullName;
        }

        return results.ToArray();
    }

    private static void AddLockfile(AnalysisContext context, DependencyInventoryState state, string lockfile)
    {
        var relativePath = DependencyInventorySupport.Relative(context, lockfile);
        if (state.Lockfiles.Any(existing =>
                existing.Ecosystem == DependencyEcosystem.Npm &&
                existing.FilePath.Equals(relativePath, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        state.Lockfiles.Add(new DependencyLockfileInfo(
            DependencyEcosystem.Npm,
            relativePath,
            Path.GetFileName(lockfile)));
    }

    private sealed record NpmSourceKind(string Kind, bool IsRemote, bool IsLocal);
}

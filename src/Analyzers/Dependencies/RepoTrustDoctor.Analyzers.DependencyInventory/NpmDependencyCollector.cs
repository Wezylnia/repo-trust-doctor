using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class NpmDependencyCollector : IDependencyInventoryCollector
{
    private const int MaxDetailedLocalSourceFindingsPerManifest = 10;
    private static readonly string[] LockfileNames = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        var lockResolvers = new Dictionary<string, NpmPackageLockResolver?>(StringComparer.OrdinalIgnoreCase);
        foreach (var manifest in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeManifest(context, state, manifest, lockResolvers);
        }
    }

    private static void AnalyzeManifest(
        AnalysisContext context,
        DependencyInventoryState state,
        string manifest,
        Dictionary<string, NpmPackageLockResolver?> lockResolvers)
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

            var localSources = new List<NpmLocalSourceDependency>();
            ReadDependencySection(root, "dependencies", DependencyScope.Production, relativePath, directory, coveringLockfiles, lockResolvers, context, state, localSources);
            ReadDependencySection(root, "devDependencies", DependencyScope.Development, relativePath, directory, coveringLockfiles, lockResolvers, context, state, localSources);
            ReadDependencySection(root, "optionalDependencies", DependencyScope.Optional, relativePath, directory, coveringLockfiles, lockResolvers, context, state, localSources);
            ReadDependencySection(root, "peerDependencies", DependencyScope.Peer, relativePath, directory, coveringLockfiles, lockResolvers, context, state, localSources);
            AddLocalSourceFindings(relativePath, localSources, state);
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
        string manifestDirectory,
        string[] coveringLockfiles,
        Dictionary<string, NpmPackageLockResolver?> lockResolvers,
        AnalysisContext context,
        DependencyInventoryState state,
        List<NpmLocalSourceDependency> localSources)
    {
        if (!root.TryGetProperty(sectionName, out var section) || section.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var dependency in section.EnumerateObject())
        {
            var version = dependency.Value.ValueKind == JsonValueKind.String ? dependency.Value.GetString() : null;
            var requestedVersion = DependencyInventorySupport.NormalizeVersion(version);
            var sourceKind = ClassifyVersionSpec(requestedVersion);
            var resolved = TryResolveLockedVersion(
                dependency.Name,
                requestedVersion,
                sourceKind,
                manifestDirectory,
                coveringLockfiles,
                lockResolvers,
                context,
                state,
                out var resolvedVersion,
                out var resolvingLockfile);
            var effectiveVersion = resolved ? resolvedVersion : requestedVersion;
            var pinned = IsPinnedVersion(effectiveVersion);
            var prerelease = DependencyInventorySupport.IsPrereleaseVersion(effectiveVersion);
            var metadata = new Dictionary<string, string>
            {
                ["section"] = sectionName,
                ["sourceKind"] = sourceKind.Kind
            };
            if (resolved)
            {
                metadata["requestedVersion"] = requestedVersion ?? string.Empty;
                metadata["versionSource"] = "package-lock";
            }

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Npm,
                dependency.Name,
                effectiveVersion,
                scope,
                manifestPath,
                resolvingLockfile ?? (coveringLockfiles.Length == 0 ? null : DependencyInventorySupport.Relative(context, coveringLockfiles[0])),
                true,
                pinned,
                prerelease,
                metadata));

            AddVersionFindings(
                dependency.Name,
                sectionName,
                requestedVersion,
                pinned,
                prerelease,
                sourceKind,
                manifestPath,
                coveringLockfiles.Length > 0,
                IsLowSignalPrereleaseManifest(manifestPath),
                localSources,
                state);
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
        bool suppressPrereleaseFinding,
        List<NpmLocalSourceDependency> localSources,
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

        if (prerelease && !suppressPrereleaseFinding)
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
            AddSourceFinding(name, sectionName, version, sourceKind, manifestPath, localSources, state);
        }
    }

    private static bool IsLowSignalPrereleaseManifest(string manifestPath)
    {
        var classification = RepositoryPathClassifier.Classify(manifestPath);
        return classification.HasAny(
            RepositoryPathClassification.Test |
            RepositoryPathClassification.Fixture |
            RepositoryPathClassification.Example |
            RepositoryPathClassification.Documentation |
            RepositoryPathClassification.Generated |
            RepositoryPathClassification.Template |
            RepositoryPathClassification.Tooling);
    }

    private static void AddSourceFinding(
        string name,
        string sectionName,
        string? version,
        NpmSourceKind sourceKind,
        string manifestPath,
        List<NpmLocalSourceDependency> localSources,
        DependencyInventoryState state)
    {
        var remote = sourceKind.IsRemote;
        if (!remote && DependencyInventorySupport.IsLikelyExampleOrTestPath(manifestPath))
        {
            return;
        }

        if (!remote)
        {
            localSources.Add(new NpmLocalSourceDependency(name, sectionName, DependencyInventorySupport.DisplayVersion(version)));
            return;
        }

        state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
            "TRUST-DEP011",
            "npm dependency uses a direct remote source",
            Severity.Medium,
            Confidence.High,
            $"npm dependency `{name}` points directly at a remote source.",
            "npm-package",
            $"Package `{name}` in `{sectionName}` uses `{DependencyInventorySupport.DisplayVersion(version)}`.",
            manifestPath,
            "Review direct remote dependency sources and prefer registry packages with pinned versions when possible."));
    }

    private static void AddLocalSourceFindings(string manifestPath, List<NpmLocalSourceDependency> localSources, DependencyInventoryState state)
    {
        if (localSources.Count == 0)
        {
            return;
        }

        if (localSources.Count <= MaxDetailedLocalSourceFindingsPerManifest)
        {
            foreach (var dependency in localSources)
            {
                state.Findings.Add(CreateLocalSourceFinding(
                    manifestPath,
                    $"npm dependency `{dependency.Name}` points at a local source.",
                    $"Package `{dependency.Name}` in `{dependency.SectionName}` uses `{dependency.Version}`."));
            }

            return;
        }

        var sample = string.Join(", ", localSources.Take(MaxDetailedLocalSourceFindingsPerManifest).Select(dependency => dependency.Name));
        state.Findings.Add(CreateLocalSourceFinding(
            manifestPath,
            $"npm manifest contains {localSources.Count} local file, link, or portal dependencies.",
            $"Manifest contains {localSources.Count} local npm dependency sources. Sample packages: {sample}."));
    }

    private static Finding CreateLocalSourceFinding(string manifestPath, string message, string evidence) =>
        DependencyInventorySupport.CreateDependencyFinding(
            "TRUST-DEP012",
            "npm dependency uses a local file source",
            Severity.Low,
            Confidence.High,
            message,
            "npm-package",
            evidence,
            manifestPath,
            "Review local dependency sources because they depend on repository layout and may bypass registry provenance.");

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
        NpmPackageLockResolver.IsExactVersion(version);

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
            : value.StartsWith("npm:", StringComparison.OrdinalIgnoreCase)
            ? new NpmSourceKind("alias", false, false)
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

    private static bool TryResolveLockedVersion(
        string packageName,
        string? requestedVersion,
        NpmSourceKind sourceKind,
        string manifestDirectory,
        IReadOnlyList<string> coveringLockfiles,
        Dictionary<string, NpmPackageLockResolver?> lockResolvers,
        AnalysisContext context,
        DependencyInventoryState state,
        out string? resolvedVersion,
        out string? resolvingLockfile)
    {
        resolvedVersion = null;
        resolvingLockfile = null;
        if (sourceKind.Kind != "registry" || IsPinnedVersion(requestedVersion))
        {
            return false;
        }

        foreach (var lockfile in coveringLockfiles.Where(path =>
                     Path.GetFileName(path).Equals("package-lock.json", StringComparison.OrdinalIgnoreCase)))
        {
            if (!lockResolvers.TryGetValue(lockfile, out var resolver))
            {
                var relativePath = DependencyInventorySupport.Relative(context, lockfile);
                NpmPackageLockResolver.TryLoad(lockfile, relativePath, state.Warnings, out resolver);
                lockResolvers[lockfile] = resolver;
            }

            if (resolver?.TryResolve(manifestDirectory, packageName, out var version) == true)
            {
                resolvedVersion = version;
                resolvingLockfile = DependencyInventorySupport.Relative(context, lockfile);
                return true;
            }
        }

        return false;
    }

    private sealed record NpmSourceKind(string Kind, bool IsRemote, bool IsLocal);

    private sealed record NpmLocalSourceDependency(string Name, string SectionName, string Version);
}

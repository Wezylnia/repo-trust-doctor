using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class PythonDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Pipfile.lock", "poetry.lock", "uv.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        var lockfiles = LockfileNames
            .SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var lockResolvers = new Dictionary<string, PythonLockfileResolver?>(StringComparer.OrdinalIgnoreCase);

        foreach (var lockfile in lockfiles)
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Python,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var requirements in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "requirements.txt"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeRequirements(context, requirements, lockResolvers, state);
        }

        foreach (var pyproject in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pyproject.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePyproject(context, pyproject, lockResolvers, state);
        }

        foreach (var pipfile in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Pipfile"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePipfile(context, pipfile, lockResolvers, state);
        }
    }

    private static void AnalyzeRequirements(
        AnalysisContext context,
        string filePath,
        Dictionary<string, PythonLockfileResolver?> lockResolvers,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        var lockfile = FindLockfile(context, filePath, LockfileNames, lockResolvers, state, out var hasLockfile);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "requirements.txt"));
        AddMissingLockfileFinding(relativePath, hasLockfile, state, "No sibling Pipfile.lock, poetry.lock, or uv.lock was found.");

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        foreach (var line in DependencyInventorySupport.SplitLines(content))
        {
            AddRequirement(relativePath, line, DependencyScope.Production, lockfile, state);
        }
    }

    private static void AnalyzePyproject(
        AnalysisContext context,
        string filePath,
        Dictionary<string, PythonLockfileResolver?> lockResolvers,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        var lockfile = FindLockfile(
            context,
            filePath,
            ["poetry.lock", "uv.lock"],
            lockResolvers,
            state,
            out var hasLockfile);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "pyproject.toml"));
        AddMissingLockfileFinding(relativePath, hasLockfile, state, "Neither a sibling poetry.lock nor uv.lock was found.");

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var section = PythonTomlSection.None;
        var inProjectDependencies = false;
        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = ReadTomlSection(line);
                inProjectDependencies = false;
                continue;
            }

            if (section == PythonTomlSection.Project)
            {
                ReadProjectDependencyLine(relativePath, line, ref inProjectDependencies, lockfile, state);
                continue;
            }

            if (section is PythonTomlSection.PoetryProduction or PythonTomlSection.PoetryDevelopment)
            {
                AddPoetryDependency(relativePath, line, section, lockfile, state);
            }
        }
    }

    private static void ReadProjectDependencyLine(
        string relativePath,
        string line,
        ref bool inProjectDependencies,
        PythonLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        if (!inProjectDependencies)
        {
            if (!line.StartsWith("dependencies", StringComparison.OrdinalIgnoreCase) || !line.Contains('['))
            {
                return;
            }

            var afterOpenBracket = line[(line.IndexOf('[', StringComparison.Ordinal) + 1)..];
            AddQuotedRequirements(relativePath, afterOpenBracket, DependencyScope.Production, lockfile, state);
            inProjectDependencies = !afterOpenBracket.Contains(']');
            return;
        }

        AddQuotedRequirements(relativePath, line, DependencyScope.Production, lockfile, state);
        if (line.Contains(']'))
        {
            inProjectDependencies = false;
        }
    }

    private static void AddQuotedRequirements(
        string relativePath,
        string value,
        DependencyScope scope,
        PythonLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        foreach (Match match in QuotedRequirementPattern().Matches(value))
        {
            AddRequirement(relativePath, match.Groups["requirement"].Value, scope, lockfile, state);
        }
    }

    private static void AnalyzePipfile(
        AnalysisContext context,
        string filePath,
        Dictionary<string, PythonLockfileResolver?> lockResolvers,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        var lockfile = FindLockfile(
            context,
            filePath,
            ["Pipfile.lock"],
            lockResolvers,
            state,
            out var hasLockfile);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "Pipfile"));
        AddMissingLockfileFinding(relativePath, hasLockfile, state, "No sibling Pipfile.lock was found.");

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var scope = DependencyScope.Unknown;
        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.Equals("[packages]", StringComparison.OrdinalIgnoreCase))
            {
                scope = DependencyScope.Production;
                continue;
            }

            if (line.Equals("[dev-packages]", StringComparison.OrdinalIgnoreCase))
            {
                scope = DependencyScope.Development;
                continue;
            }

            if (scope == DependencyScope.Unknown || string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || !line.Contains('='))
            {
                continue;
            }

            var parts = line.Split('=', 2, StringSplitOptions.TrimEntries);
            ParseVersionSpec(parts[1].Trim('"'), out var operatorText, out var version);
            AddPythonPackage(relativePath, parts[0], version, scope, operatorText, lockfile, state);
        }
    }

    private static void AddPoetryDependency(
        string relativePath,
        string line,
        PythonTomlSection section,
        PythonLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || !line.Contains('='))
        {
            return;
        }

        var parts = line.Split('=', 2, StringSplitOptions.TrimEntries);
        var name = parts[0].Trim('"');
        if (name.Equals("python", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var scope = section == PythonTomlSection.PoetryDevelopment ? DependencyScope.Development : DependencyScope.Production;
        AddPythonPackage(relativePath, name, parts[1].Trim('"'), scope, null, lockfile, state);
    }

    private static void AddRequirement(
        string relativePath,
        string line,
        DependencyScope scope,
        PythonLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        var trimmed = line.Trim();
        if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith('-'))
        {
            return;
        }

        var match = RequirementPattern().Match(trimmed);
        if (!match.Success)
        {
            return;
        }

        var op = match.Groups["op"].Success ? match.Groups["op"].Value : null;
        var version = match.Groups["version"].Success ? match.Groups["version"].Value : null;
        AddPythonPackage(relativePath, match.Groups["name"].Value, version, scope, op, lockfile, state);
    }

    private static void AddPythonPackage(
        string relativePath,
        string name,
        string? version,
        DependencyScope scope,
        string? operatorText,
        PythonLockfileResolver? lockfile,
        DependencyInventoryState state)
    {
        var requestedVersion = DependencyInventorySupport.NormalizeVersion(version);
        string? resolvedVersion = null;
        var resolved = lockfile is not null && lockfile.TryResolve(name, out resolvedVersion);
        var effectiveVersion = resolved ? resolvedVersion : requestedVersion;
        var pinned = resolved || operatorText == "==" || (operatorText is null && IsPinnedVersion(effectiveVersion));
        var prerelease = IsPythonPrerelease(effectiveVersion);
        var metadata = new Dictionary<string, string>();
        if (operatorText is not null)
        {
            metadata["operator"] = operatorText;
        }

        if (resolved)
        {
            metadata["requestedVersion"] = requestedVersion ?? string.Empty;
            metadata["versionSource"] = lockfile!.RelativePath;
        }

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Python,
            name.Trim(),
            effectiveVersion,
            scope,
            relativePath,
            lockfile?.RelativePath,
            true,
            pinned,
            prerelease,
            metadata.Count == 0 ? null : metadata));

        AddVersionFindings(relativePath, name.Trim(), effectiveVersion, pinned, prerelease, state);
    }

    private static void AddVersionFindings(
        string relativePath,
        string name,
        string? version,
        bool pinned,
        bool prerelease,
        DependencyInventoryState state)
    {
        if (DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath))
        {
            return;
        }

        if (!pinned)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP009",
                "Python requirement is unpinned",
                Severity.Medium,
                Confidence.High,
                $"Python dependency `{name}` is not pinned to an exact version.",
                "python-package",
                $"Package `{name}` version is `{DependencyInventorySupport.DisplayVersion(version)}`.",
                relativePath,
                "Pin Python requirements or use a lockfile-based package manager."));
        }

        if (prerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP010",
                "Python dependency uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"Python dependency `{name}` uses prerelease version `{version}`.",
                "python-package",
                $"Package `{name}` version is `{version}`.",
                relativePath,
                "Review whether the prerelease dependency is intentional before production use."));
        }
    }

    private static void AddMissingLockfileFinding(
        string relativePath,
        bool hasLockfile,
        DependencyInventoryState state,
        string evidence)
    {
        if (hasLockfile || DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath))
        {
            return;
        }

        state.Findings.Add(new Finding(
            "TRUST-DEP003",
            "Python dependency manifest does not have a recognized lockfile",
            AnalysisCategory.Dependencies,
            Severity.Low,
            Confidence.Medium,
            "Python dependency manifest does not have a recognized lockfile",
            [new Evidence("package-manifest", evidence, relativePath)],
            new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
    }

    private static PythonLockfileResolver? FindLockfile(
        AnalysisContext context,
        string manifestPath,
        IReadOnlyList<string> allowedNames,
        IDictionary<string, PythonLockfileResolver?> lockResolvers,
        DependencyInventoryState state,
        out bool detected)
    {
        detected = false;
        PythonLockfileResolver? emptyResolver = null;
        var directory = Path.GetDirectoryName(manifestPath);
        if (directory is null)
        {
            return null;
        }

        foreach (var lockfileName in allowedNames)
        {
            var lockfilePath = Path.Combine(directory, lockfileName);
            if (!File.Exists(lockfilePath))
            {
                continue;
            }

            detected = true;
            if (!lockResolvers.TryGetValue(lockfilePath, out var resolver))
            {
                PythonLockfileResolver.TryLoad(
                    lockfilePath,
                    DependencyInventorySupport.Relative(context, lockfilePath),
                    state.Warnings,
                    out resolver);
                lockResolvers[lockfilePath] = resolver;
            }

            if (resolver is not null)
            {
                if (resolver.HasPackages)
                {
                    return resolver;
                }

                emptyResolver ??= resolver;
            }
        }

        return emptyResolver;
    }

    private static void ParseVersionSpec(string value, out string? operatorText, out string? version)
    {
        var match = PythonVersionSpecPattern().Match(value.Trim());
        operatorText = match.Groups["op"].Success ? match.Groups["op"].Value : null;
        version = match.Groups["version"].Success ? match.Groups["version"].Value : null;
    }

    private static PythonTomlSection ReadTomlSection(string line) =>
        line switch
        {
            "[project]" => PythonTomlSection.Project,
            "[tool.poetry.dependencies]" => PythonTomlSection.PoetryProduction,
            "[tool.poetry.group.dev.dependencies]" => PythonTomlSection.PoetryDevelopment,
            _ => PythonTomlSection.None
        };

    private static bool IsPinnedVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        DependencyInventorySupport.ExactSemVerPattern().IsMatch(version);

    private static bool IsPythonPrerelease(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        Regex.IsMatch(version, @"\d+\.\d+(\.\d+)?(?:a|b|rc|dev|alpha|beta|pre|preview)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    [GeneratedRegex(@"^(?<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?<op>===|==|~=|!=|<=|>=|<|>)?\s*(?<version>[^\s;]+)?", RegexOptions.CultureInvariant)]
    private static partial Regex RequirementPattern();

    [GeneratedRegex(@"['""](?<requirement>[^'""]+)['""]", RegexOptions.CultureInvariant)]
    private static partial Regex QuotedRequirementPattern();

    [GeneratedRegex(@"^(?<op>===|==|~=|!=|<=|>=|<|>)?\s*(?<version>.+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex PythonVersionSpecPattern();

    private enum PythonTomlSection
    {
        None,
        Project,
        PoetryProduction,
        PoetryDevelopment
    }
}

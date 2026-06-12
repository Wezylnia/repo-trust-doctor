using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class PythonDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Pipfile.lock", "poetry.lock", "uv.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Python,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        foreach (var requirements in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "requirements.txt"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeRequirements(context, requirements, state);
        }

        foreach (var pyproject in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "pyproject.toml"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePyproject(context, pyproject, state);
        }

        foreach (var pipfile in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Pipfile"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzePipfile(context, pipfile, state);
        }
    }

    private static void AnalyzeRequirements(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "requirements.txt"));
        AddMissingLockfileFinding(relativePath, state, "No Pipfile.lock, poetry.lock, or uv.lock was found.");

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        foreach (var line in DependencyInventorySupport.SplitLines(content))
        {
            AddRequirement(relativePath, line, DependencyScope.Production, state);
        }
    }

    private static void AnalyzePyproject(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "pyproject.toml"));
        AddMissingLockfileFinding(relativePath, state, "Neither poetry.lock nor uv.lock was found.");

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
                ReadProjectDependencyLine(relativePath, line, ref inProjectDependencies, state);
                continue;
            }

            if (section is PythonTomlSection.PoetryProduction or PythonTomlSection.PoetryDevelopment)
            {
                AddPoetryDependency(relativePath, line, section, state);
            }
        }
    }

    private static void ReadProjectDependencyLine(
        string relativePath,
        string line,
        ref bool inProjectDependencies,
        DependencyInventoryState state)
    {
        if (!inProjectDependencies)
        {
            if (!line.StartsWith("dependencies", StringComparison.OrdinalIgnoreCase) || !line.Contains('['))
            {
                return;
            }

            var afterOpenBracket = line[(line.IndexOf('[', StringComparison.Ordinal) + 1)..];
            AddQuotedRequirements(relativePath, afterOpenBracket, DependencyScope.Production, state);
            inProjectDependencies = !afterOpenBracket.Contains(']');
            return;
        }

        AddQuotedRequirements(relativePath, line, DependencyScope.Production, state);
        if (line.Contains(']'))
        {
            inProjectDependencies = false;
        }
    }

    private static void AddQuotedRequirements(
        string relativePath,
        string value,
        DependencyScope scope,
        DependencyInventoryState state)
    {
        foreach (Match match in QuotedRequirementPattern().Matches(value))
        {
            AddRequirement(relativePath, match.Groups["requirement"].Value, scope, state);
        }
    }

    private static void AnalyzePipfile(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Python, relativePath, "Pipfile"));
        if (!state.Lockfiles.Any(lockfile => lockfile.Kind.Equals("Pipfile.lock", StringComparison.OrdinalIgnoreCase)))
        {
            AddMissingLockfileFinding(relativePath, state, "No Pipfile.lock was found.");
        }

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
            AddPythonPackage(relativePath, parts[0], parts[1].Trim('"'), scope, null, state);
        }
    }

    private static void AddPoetryDependency(string relativePath, string line, PythonTomlSection section, DependencyInventoryState state)
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
        AddPythonPackage(relativePath, name, parts[1].Trim('"'), scope, null, state);
    }

    private static void AddRequirement(string relativePath, string line, DependencyScope scope, DependencyInventoryState state)
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
        AddPythonPackage(relativePath, match.Groups["name"].Value, version, scope, op, state);
    }

    private static void AddPythonPackage(
        string relativePath,
        string name,
        string? version,
        DependencyScope scope,
        string? operatorText,
        DependencyInventoryState state)
    {
        var normalizedVersion = DependencyInventorySupport.NormalizeVersion(version);
        var pinned = operatorText == "==" || (operatorText is null && IsPinnedVersion(normalizedVersion));
        var prerelease = IsPythonPrerelease(normalizedVersion);
        var metadata = operatorText is null
            ? null
            : new Dictionary<string, string> { ["operator"] = operatorText };

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Python,
            name.Trim(),
            normalizedVersion,
            scope,
            relativePath,
            null,
            true,
            pinned,
            prerelease,
            metadata));

        AddVersionFindings(relativePath, name.Trim(), normalizedVersion, pinned, prerelease, state);
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

    private static void AddMissingLockfileFinding(string relativePath, DependencyInventoryState state, string evidence)
    {
        if (state.Lockfiles.Any(lockfile => lockfile.Ecosystem == DependencyEcosystem.Python) ||
            DependencyInventorySupport.IsLikelyExampleOrTestPath(relativePath))
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

    [GeneratedRegex(@"^(?<name>[A-Za-z0-9_.-]+)\s*(?<op>===|==|~=|!=|<=|>=|<|>)?\s*(?<version>[^\s;]+)?", RegexOptions.CultureInvariant)]
    private static partial Regex RequirementPattern();

    [GeneratedRegex(@"['""](?<requirement>[^'""]+)['""]", RegexOptions.CultureInvariant)]
    private static partial Regex QuotedRequirementPattern();

    private enum PythonTomlSection
    {
        None,
        Project,
        PoetryProduction,
        PoetryDevelopment
    }
}

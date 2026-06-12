using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class BundlerDependencyCollector : IDependencyInventoryCollector
{
    private static readonly string[] LockfileNames = ["Gemfile.lock"];

    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var lockfile in LockfileNames.SelectMany(name => RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, name)))
        {
            state.Lockfiles.Add(new DependencyLockfileInfo(
                DependencyEcosystem.Ruby,
                DependencyInventorySupport.Relative(context, lockfile),
                Path.GetFileName(lockfile)));
        }

        var gemfiles = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "Gemfile")
            .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.gemspec"))
            .ToArray();

        foreach (var file in gemfiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Path.GetFileName(file).Equals("Gemfile", StringComparison.OrdinalIgnoreCase))
            {
                AnalyzeGemfile(context, file, state);
            }
            else if (file.EndsWith(".gemspec", StringComparison.OrdinalIgnoreCase))
            {
                AnalyzeGemspec(context, file, state);
            }
        }
    }

    private static void AnalyzeGemfile(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Ruby, relativePath, "Gemfile"));

        var hasSiblingLockfile = HasSiblingLockfile(filePath);
        if (!hasSiblingLockfile)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP034",
                "Ruby Gemfile does not have a Gemfile.lock",
                Severity.Medium,
                Confidence.High,
                "A Gemfile exists but no Gemfile.lock was found.",
                "package-manifest",
                "No Gemfile.lock was found alongside Gemfile.",
                relativePath,
                "Run 'bundle install' and commit Gemfile.lock to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        var currentScope = DependencyScope.Production;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            // Track group scoping
            if (line.StartsWith("group ", StringComparison.Ordinal) && line.Contains(":development", StringComparison.Ordinal))
            {
                currentScope = DependencyScope.Development;
                continue;
            }
            if (line == "end")
            {
                currentScope = DependencyScope.Production;
                continue;
            }

            if (!line.StartsWith("gem ", StringComparison.Ordinal))
            {
                continue;
            }

            ParseGemDeclaration(relativePath, line, currentScope, hasSiblingLockfile, state);
        }
    }

    private static void AnalyzeGemspec(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Ruby, relativePath, Path.GetFileName(filePath)));

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var isRuntimeDep = Regex.Match(line, @"spec\.add_dependency\s+");
            var isDevDep = Regex.Match(line, @"spec\.add_development_dependency\s+");

            if (!isRuntimeDep.Success && !isDevDep.Success)
            {
                continue;
            }

            var scope = isDevDep.Success ? DependencyScope.Development : DependencyScope.Production;
            var match = GemspecDepPattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var gemName = match.Groups["name"].Value.Trim('"', '\'');
            var constraint = match.Groups["constraint"].Value.Trim('"', '\'');

            AddRubyPackage(relativePath, gemName, constraint, scope, true, state);
        }
    }

    private static void ParseGemDeclaration(
        string manifestPath,
        string line,
        DependencyScope scope,
        bool hasSiblingLockfile,
        DependencyInventoryState state)
    {
        var match = GemDeclarationPattern().Match(line);
        if (!match.Success)
        {
            return;
        }

        var gemName = match.Groups["name"].Value.Trim('"', '\'');
        var constraint = match.Groups["constraint"].Success ? match.Groups["constraint"].Value.Trim('"', '\'') : null;
        var isGit = match.Groups["git"].Success;
        var isPath = match.Groups["path"].Success;

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (isGit)
        {
            metadata["sourceKind"] = "git";
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP036",
                "Ruby gem uses a Git source",
                Severity.Medium,
                Confidence.High,
                $"Ruby gem '{gemName}' references a Git source instead of a registry version.",
                "gem-git-source",
                $"Gem '{gemName}' uses a Git source.",
                manifestPath,
                "Review Git-sourced gems and prefer RubyGems packages with pinned versions when possible."));
        }

        if (isPath)
        {
            metadata["sourceKind"] = "path";
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP036",
                "Ruby gem uses a path source",
                Severity.Low,
                Confidence.High,
                $"Ruby gem '{gemName}' references a local path instead of a registry version.",
                "gem-path-source",
                $"Gem '{gemName}' uses a path source.",
                manifestPath,
                "Review path-sourced gems because they depend on repository layout and may bypass registry provenance."));
        }

        AddRubyPackage(manifestPath, gemName, constraint, scope, !hasSiblingLockfile, state, metadata);
    }

    private static void AddRubyPackage(
        string manifestPath,
        string gemName,
        string? constraint,
        DependencyScope scope,
        bool emitConstraintFinding,
        DependencyInventoryState state,
        Dictionary<string, string>? metadata = null)
    {
        var isPinned = IsExactGemConstraint(constraint);
        var isPrerelease = IsRubyPrerelease(constraint);

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Ruby,
            gemName,
            constraint,
            scope,
            manifestPath,
            null,
            true,
            isPinned,
            isPrerelease,
            metadata?.Count > 0 ? metadata : null));

        if (!isPinned && emitConstraintFinding)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP035",
                "Ruby gem uses a non-exact version constraint",
                Severity.Medium,
                Confidence.High,
                $"Ruby gem '{gemName}' uses a non-exact or missing version constraint.",
                "gem-constraint",
                $"Gem '{gemName}' has version constraint '{DependencyInventorySupport.DisplayVersion(constraint)}'.",
                manifestPath,
                "Use exact gem versions with a committed Gemfile.lock for reproducible builds."));
        }

        if (isPrerelease)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP049",
                "Ruby gem uses a prerelease version",
                Severity.Low,
                Confidence.High,
                $"Ruby gem '{gemName}' uses a prerelease version.",
                "gem-prerelease",
                $"Gem '{gemName}' has prerelease version '{constraint}'.",
                manifestPath,
                "Review whether the prerelease gem is intentional before production use."));
        }
    }

    private static bool HasSiblingLockfile(string gemfilePath)
    {
        var directory = Path.GetDirectoryName(gemfilePath);
        return directory is not null && File.Exists(Path.Combine(directory, "Gemfile.lock"));
    }

    private static bool IsExactGemConstraint(string? constraint)
    {
        if (string.IsNullOrWhiteSpace(constraint))
        {
            return false;
        }

        var value = constraint.Trim();
        if (value.StartsWith('='))
        {
            value = value[1..].Trim();
        }

        return ExactGemVersionPattern().IsMatch(value);
    }

    private static bool IsRubyPrerelease(string? constraint)
    {
        if (string.IsNullOrWhiteSpace(constraint))
        {
            return false;
        }

        var value = constraint.Trim();
        if (value.StartsWith('='))
        {
            value = value[1..].Trim();
        }

        return RubyPrereleasePattern().IsMatch(value);
    }

    [GeneratedRegex(@"gem\s+['""](?<name>[^'""]+)['""](?:\s*,\s*['""](?<constraint>[^'""]+)['""])?(?:.*git:\s*['""](?<git>[^'""]+)['""])?(?:.*path:\s*['""](?<path>[^'""]+)['""])?")]
    private static partial Regex GemDeclarationPattern();

    [GeneratedRegex(@"spec\.add_(?:development_)?dependency\s+['""](?<name>[^'""]+)['""]\s*,\s*['""](?<constraint>[^'""]+)['""]")]
    private static partial Regex GemspecDepPattern();

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")]
    private static partial Regex ExactGemVersionPattern();

    [GeneratedRegex(@"\d+\.\d+\.\d+(?:[-.]|\.)(alpha|beta|pre|preview|rc|dev)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RubyPrereleasePattern();
}

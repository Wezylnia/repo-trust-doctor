using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

public sealed class DependencyInventoryAnalyzer : IRepositoryAnalyzer
{
    public string Id => "dependency-inventory";

    public string DisplayName => "Dependency Inventory";

    public AnalysisCategory Category => AnalysisCategory.Dependencies;

    public AnalysisDepth MinimumDepth => AnalysisDepth.Standard;

    public IReadOnlyCollection<string> DependsOn => [];

    public AnalyzerExecutionSafety ExecutionSafety => AnalyzerExecutionSafety.StaticOnly;

    public TimeSpan Timeout => TimeSpan.FromSeconds(10);

    public IReadOnlyCollection<RuleMetadata> Rules =>
    [
        new("TRUST-DEP001", "npm manifest exists without lockfile", AnalysisCategory.Dependencies, Severity.Medium, Confidence.High, "A package.json file exists but no lockfile was found.", "Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository."),
        new("TRUST-DEP002", "NuGet project does not use lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A NuGet project exists but no packages.lock.json was found.", "Enable NuGet lock files and commit packages.lock.json to the repository."),
        new("TRUST-DEP003", "Python dependency manifest does not have a recognized lockfile", AnalysisCategory.Dependencies, Severity.Low, Confidence.Medium, "A Python dependency manifest exists but no recognized lockfile was found.", "Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")
    ];

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Detect npm manifests and lockfiles
        var packageJsons = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "package.json").ToArray();
        foreach (var manifest in packageJsons)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = Path.GetDirectoryName(manifest);
            if (directory == null)
            {
                continue;
            }

            var hasLockfile = File.Exists(Path.Combine(directory, "package-lock.json")) ||
                              File.Exists(Path.Combine(directory, "pnpm-lock.yaml")) ||
                              File.Exists(Path.Combine(directory, "yarn.lock"));

            if (!hasLockfile)
            {
                var relativePath = Path.GetRelativePath(context.RepositoryPath, manifest);
                findings.Add(new Finding(
                    "TRUST-DEP001",
                    "npm manifest exists without lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Medium,
                    Confidence.High,
                    "npm manifest exists without lockfile",
                    [new Evidence("package-manifest", "A package.json file exists but no lockfile was found.", relativePath)],
                    new Recommendation("Commit package-lock.json, pnpm-lock.yaml, or yarn.lock to the repository.")));
            }
        }

        // Detect NuGet projects and lockfiles
        var csprojs = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "*.csproj").ToArray();
        if (csprojs.Length > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hasNuGetLockfile = RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "packages.lock.json").Any();
            if (!hasNuGetLockfile)
            {
                var representativeProject = csprojs[0];
                var relativePath = Path.GetRelativePath(context.RepositoryPath, representativeProject);
                findings.Add(new Finding(
                    "TRUST-DEP002",
                    "NuGet project does not use lockfile",
                    AnalysisCategory.Dependencies,
                    Severity.Low,
                    Confidence.Medium,
                    "NuGet project does not use lockfile",
                    [new Evidence("package-manifest", "A NuGet project exists but no packages.lock.json was found.", relativePath)],
                    new Recommendation("Enable NuGet lock files and restore locked mode, then commit packages.lock.json to the repository.")));
            }
        }

        // Detect Python manifests and lockfiles (root-level only)
        var pipfilePath = Path.Combine(context.RepositoryPath, "Pipfile");
        var pyprojectPath = Path.Combine(context.RepositoryPath, "pyproject.toml");
        var requirementsPath = Path.Combine(context.RepositoryPath, "requirements.txt");

        var hasPipfile = File.Exists(pipfilePath);
        var hasPyproject = File.Exists(pyprojectPath);
        var hasRequirements = File.Exists(requirementsPath);

        var hasPipfileLock = File.Exists(Path.Combine(context.RepositoryPath, "Pipfile.lock"));
        var hasPoetryLock = File.Exists(Path.Combine(context.RepositoryPath, "poetry.lock"));
        var hasUvLock = File.Exists(Path.Combine(context.RepositoryPath, "uv.lock"));

        if (hasPipfile && !hasPipfileLock)
        {
            var relativePath = Path.GetRelativePath(context.RepositoryPath, pipfilePath);
            findings.Add(new Finding(
                "TRUST-DEP003",
                "Python dependency manifest does not have a recognized lockfile",
                AnalysisCategory.Dependencies,
                Severity.Low,
                Confidence.Medium,
                "Python dependency manifest does not have a recognized lockfile",
                [new Evidence("package-manifest", "A Pipfile exists but no Pipfile.lock was found.", relativePath)],
                new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
        }
        else if (hasPyproject && !hasPoetryLock && !hasUvLock)
        {
            var relativePath = Path.GetRelativePath(context.RepositoryPath, pyprojectPath);
            findings.Add(new Finding(
                "TRUST-DEP003",
                "Python dependency manifest does not have a recognized lockfile",
                AnalysisCategory.Dependencies,
                Severity.Low,
                Confidence.Medium,
                "Python dependency manifest does not have a recognized lockfile",
                [new Evidence("package-manifest", "A pyproject.toml exists but neither poetry.lock nor uv.lock was found.", relativePath)],
                new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
        }
        else if (hasRequirements && !hasPipfileLock && !hasPoetryLock && !hasUvLock)
        {
            var relativePath = Path.GetRelativePath(context.RepositoryPath, requirementsPath);
            findings.Add(new Finding(
                "TRUST-DEP003",
                "Python dependency manifest does not have a recognized lockfile",
                AnalysisCategory.Dependencies,
                Severity.Low,
                Confidence.Medium,
                "Python dependency manifest does not have a recognized lockfile",
                [new Evidence("package-manifest", "A requirements.txt exists but no recognized lockfile was found.", relativePath)],
                new Recommendation("Use a package manager like Poetry, uv, or Pipenv, and commit the lockfile to the repository.")));
        }

        return Task.FromResult(AnalyzerResult.Completed(findings));
    }
}

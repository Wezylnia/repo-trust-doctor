using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class CppDependencyCollector : IDependencyInventoryCollector
{
    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "conanfile.txt")
                     .Concat(RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "conanfile.py")))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = DependencyInventorySupport.Relative(context, file);
            state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Cpp, relativePath, Path.GetFileName(file)));
            AnalyzeConanfile(context, file, relativePath, state);
        }

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "vcpkg.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = DependencyInventorySupport.Relative(context, file);
            state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Cpp, relativePath, "vcpkg.json"));
            AnalyzeVcpkgJson(context, file, relativePath, state);
        }

        foreach (var file in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "CMakeLists.txt"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = DependencyInventorySupport.Relative(context, file);
            AnalyzeCmakeLists(context, file, relativePath, state);
        }
    }

    private static void AnalyzeConanfile(AnalysisContext context, string filePath, string relativePath, DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var match = ConanRequirePattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var pkgName = match.Groups["name"].Value;
            var version = match.Groups["version"].Success ? match.Groups["version"].Value : null;

            state.Packages.Add(new DependencyPackageInfo(
                DependencyEcosystem.Cpp,
                pkgName,
                version,
                DependencyScope.Production,
                relativePath,
                null,
                true,
                version != null,
                false,
                null));
        }
    }

    private static void AnalyzeVcpkgJson(AnalysisContext context, string filePath, string relativePath, DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(content, new System.Text.Json.JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = System.Text.Json.JsonCommentHandling.Skip
            });

            if (document.RootElement.TryGetProperty("dependencies", out var deps) && deps.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var dep in deps.EnumerateArray())
                {
                    var name = ReadVcpkgDependencyName(dep);
                    var version = ReadVcpkgDependencyVersion(dep);

                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        state.Packages.Add(new DependencyPackageInfo(
                            DependencyEcosystem.Cpp,
                            name,
                            version,
                            DependencyScope.Production,
                            relativePath,
                            null,
                            true,
                            version != null,
                            false,
                            null));
                    }
                }
            }
        }
        catch (System.Text.Json.JsonException ex)
        {
            state.Warnings.Add($"Could not parse vcpkg.json '{relativePath}': {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            state.Warnings.Add($"Could not parse vcpkg.json '{relativePath}': {ex.Message}");
        }
    }

    private static void AnalyzeCmakeLists(AnalysisContext context, string filePath, string relativePath, DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var hasExternalDeps = false;
        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            if (CmakeFindPackagePattern().IsMatch(line) || CmakeFetchContentPattern().IsMatch(line))
            {
                hasExternalDeps = true;
                break;
            }
        }

        if (hasExternalDeps)
        {
            state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Cpp, relativePath, "CMakeLists.txt"));
        }
    }

    [GeneratedRegex(@"^\s*(?<name>[a-zA-Z0-9_\-\.]+)/(?<version>[^\s]+)")]
    private static partial Regex ConanRequirePattern();

    [GeneratedRegex(@"\bfind_package\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CmakeFindPackagePattern();

    [GeneratedRegex(@"\bFetchContent_Declare\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CmakeFetchContentPattern();

    private static string? ReadVcpkgDependencyName(System.Text.Json.JsonElement dependency) =>
        dependency.ValueKind switch
        {
            System.Text.Json.JsonValueKind.String => dependency.GetString(),
            System.Text.Json.JsonValueKind.Object when dependency.TryGetProperty("name", out var name) && name.ValueKind == System.Text.Json.JsonValueKind.String => name.GetString(),
            _ => null
        };

    private static string? ReadVcpkgDependencyVersion(System.Text.Json.JsonElement dependency)
    {
        if (dependency.ValueKind != System.Text.Json.JsonValueKind.Object)
        {
            return null;
        }

        foreach (var propertyName in new[] { "version>=", "version", "version-string", "version-semver", "version-date" })
        {
            if (dependency.TryGetProperty(propertyName, out var version) && version.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                return version.GetString();
            }
        }

        return null;
    }
}

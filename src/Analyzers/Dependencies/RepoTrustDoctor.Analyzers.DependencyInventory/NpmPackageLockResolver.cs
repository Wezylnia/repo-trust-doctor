using System.Text.Json;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class NpmPackageLockResolver
{
    private const long MaximumLockfileBytes = 64L * 1024 * 1024;
    private readonly string lockfileDirectory;
    private readonly IReadOnlyDictionary<string, LockedPackage> packagesByPath;
    private readonly IReadOnlyDictionary<string, LockedPackage> rootDependencies;

    private NpmPackageLockResolver(
        string lockfileDirectory,
        IReadOnlyDictionary<string, LockedPackage> packagesByPath,
        IReadOnlyDictionary<string, LockedPackage> rootDependencies)
    {
        this.lockfileDirectory = lockfileDirectory;
        this.packagesByPath = packagesByPath;
        this.rootDependencies = rootDependencies;
    }

    internal static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out NpmPackageLockResolver? resolver)
    {
        resolver = null;

        try
        {
            var fileInfo = new FileInfo(lockfilePath);
            if (fileInfo.Length > MaximumLockfileBytes)
            {
                warnings.Add(
                    $"Skipped npm lockfile '{relativePath}' because it exceeds the {MaximumLockfileBytes / (1024 * 1024)} MiB lockfile safety limit.");
                return false;
            }

            using var stream = File.OpenRead(lockfilePath);
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 128
            });

            resolver = new NpmPackageLockResolver(
                Path.GetDirectoryName(lockfilePath) ?? string.Empty,
                ReadPackages(document.RootElement),
                ReadRootDependencies(document.RootElement));
            return true;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not parse npm lockfile '{relativePath}': {ex.Message}");
            return false;
        }
    }

    internal bool TryResolve(string manifestDirectory, string packageName, out string version)
    {
        version = string.Empty;
        var relativeManifestDirectory = NormalizePath(Path.GetRelativePath(lockfileDirectory, manifestDirectory));
        if (relativeManifestDirectory.StartsWith("../", StringComparison.Ordinal) ||
            relativeManifestDirectory.Equals("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var key in CandidatePackagePaths(relativeManifestDirectory, packageName))
        {
            if (packagesByPath.TryGetValue(key, out var package) &&
                PackageMatches(package, packageName) &&
                IsExactVersion(package.Version))
            {
                version = package.Version;
                return true;
            }
        }

        if (rootDependencies.TryGetValue(packageName, out var rootPackage) &&
            PackageMatches(rootPackage, packageName) &&
            IsExactVersion(rootPackage.Version))
        {
            version = rootPackage.Version;
            return true;
        }

        return false;
    }

    internal static bool IsExactVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        NpmExactVersionPattern().IsMatch(version);

    private static IReadOnlyDictionary<string, LockedPackage> ReadPackages(JsonElement root)
    {
        var packages = new Dictionary<string, LockedPackage>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("packages", out var packageObject) ||
            packageObject.ValueKind != JsonValueKind.Object)
        {
            return packages;
        }

        foreach (var property in packageObject.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.Object ||
                !TryReadVersion(property.Value, out var version))
            {
                continue;
            }

            var name = property.Value.TryGetProperty("name", out var nameElement) &&
                       nameElement.ValueKind == JsonValueKind.String
                ? nameElement.GetString()
                : null;
            packages[NormalizePath(property.Name)] = new LockedPackage(name, version);
        }

        return packages;
    }

    private static IReadOnlyDictionary<string, LockedPackage> ReadRootDependencies(JsonElement root)
    {
        var dependencies = new Dictionary<string, LockedPackage>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("dependencies", out var dependencyObject) ||
            dependencyObject.ValueKind != JsonValueKind.Object)
        {
            return dependencies;
        }

        foreach (var property in dependencyObject.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.Object &&
                TryReadVersion(property.Value, out var version))
            {
                dependencies[property.Name] = new LockedPackage(property.Name, version);
            }
        }

        return dependencies;
    }

    private static IEnumerable<string> CandidatePackagePaths(string relativeManifestDirectory, string packageName)
    {
        var current = relativeManifestDirectory.Equals(".", StringComparison.Ordinal)
            ? string.Empty
            : relativeManifestDirectory.Trim('/');

        while (true)
        {
            yield return current.Length == 0
                ? $"node_modules/{packageName}"
                : $"{current}/node_modules/{packageName}";

            if (current.Length == 0)
            {
                break;
            }

            var separator = current.LastIndexOf('/');
            current = separator < 0 ? string.Empty : current[..separator];
        }
    }

    private static bool PackageMatches(LockedPackage package, string requestedName) =>
        string.IsNullOrWhiteSpace(package.Name) ||
        package.Name.Equals(requestedName, StringComparison.OrdinalIgnoreCase);

    private static bool TryReadVersion(JsonElement element, out string version)
    {
        version = string.Empty;
        if (!element.TryGetProperty("version", out var versionElement) ||
            versionElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        version = versionElement.GetString()?.Trim() ?? string.Empty;
        return version.Length > 0;
    }

    private static string NormalizePath(string path) =>
        path.Replace('\\', '/').TrimStart('/');

    [GeneratedRegex(
        @"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex NpmExactVersionPattern();

    private sealed record LockedPackage(string? Name, string Version);
}

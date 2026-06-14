using System.Text.Json;
using System.Text.RegularExpressions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class NuGetPackageLockResolver
{
    private const long MaximumLockfileBytes = 64L * 1024 * 1024;
    private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> directVersions;

    private NuGetPackageLockResolver(
        IReadOnlyDictionary<string, IReadOnlySet<string>> directVersions)
    {
        this.directVersions = directVersions;
    }

    internal static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out NuGetPackageLockResolver? resolver)
    {
        resolver = null;

        try
        {
            var fileInfo = new FileInfo(lockfilePath);
            if (fileInfo.Length > MaximumLockfileBytes)
            {
                warnings.Add(
                    $"Skipped NuGet lockfile '{relativePath}' because it exceeds the {MaximumLockfileBytes / (1024 * 1024)} MiB lockfile safety limit.");
                return false;
            }

            using var stream = File.OpenRead(lockfilePath);
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 128
            });

            resolver = new NuGetPackageLockResolver(ReadDirectVersions(document.RootElement));
            return true;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not parse NuGet lockfile '{relativePath}': {ex.Message}");
            return false;
        }
    }

    internal bool TryResolve(string packageName, out string version)
    {
        version = string.Empty;
        if (!directVersions.TryGetValue(packageName, out var versions) ||
            versions.Count != 1)
        {
            return false;
        }

        version = versions.Single();
        return true;
    }

    private static IReadOnlyDictionary<string, IReadOnlySet<string>> ReadDirectVersions(JsonElement root)
    {
        var versions = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("dependencies", out var targets) ||
            targets.ValueKind != JsonValueKind.Object)
        {
            return new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase);
        }

        foreach (var target in targets.EnumerateObject())
        {
            if (target.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var package in target.Value.EnumerateObject())
            {
                if (!TryReadDirectVersion(package.Value, out var version))
                {
                    continue;
                }

                if (!versions.TryGetValue(package.Name, out var packageVersions))
                {
                    packageVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    versions[package.Name] = packageVersions;
                }

                packageVersions.Add(version);
            }
        }

        return versions.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlySet<string>)pair.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static bool TryReadDirectVersion(JsonElement package, out string version)
    {
        version = string.Empty;
        if (package.ValueKind != JsonValueKind.Object ||
            !package.TryGetProperty("type", out var typeElement) ||
            typeElement.ValueKind != JsonValueKind.String ||
            !string.Equals(typeElement.GetString(), "Direct", StringComparison.OrdinalIgnoreCase) ||
            !package.TryGetProperty("resolved", out var resolvedElement) ||
            resolvedElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        version = resolvedElement.GetString()?.Trim() ?? string.Empty;
        return ExactVersionPattern().IsMatch(version);
    }

    [GeneratedRegex(
        @"^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex ExactVersionPattern();
}

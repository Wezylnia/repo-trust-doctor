using System.Text;
using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class PythonLockfileResolver
{
    private const long MaximumLockfileBytes = 64L * 1024 * 1024;
    private readonly IReadOnlyDictionary<string, string> versions;

    private PythonLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public bool HasPackages => versions.Count > 0;

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(NormalizePackageName(packageName), out version!);

    public static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out PythonLockfileResolver? resolver)
    {
        resolver = null;
        if (!RepositoryFileSystem.CanReadAsText(lockfilePath, MaximumLockfileBytes))
        {
            warnings.Add(
                $"Skipped Python lockfile '{relativePath}' because it exceeds the {MaximumLockfileBytes / (1024 * 1024)} MiB lockfile safety limit or is not readable as text.");
            return false;
        }

        try
        {
            var versions = Path.GetFileName(lockfilePath).Equals("Pipfile.lock", StringComparison.OrdinalIgnoreCase)
                ? ParsePipfileLock(lockfilePath)
                : ParseTomlLock(lockfilePath);
            resolver = new PythonLockfileResolver(relativePath, versions);
            return true;
        }
        catch (JsonException)
        {
            warnings.Add($"Could not parse Python lockfile '{relativePath}' because it contains invalid JSON.");
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not read Python lockfile '{relativePath}'.");
            return false;
        }
    }

    private static IReadOnlyDictionary<string, string> ParsePipfileLock(string lockfilePath)
    {
        using var stream = File.OpenRead(lockfilePath);
        using var document = JsonDocument.Parse(stream);
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var sectionName in new[] { "default", "develop" })
        {
            if (!document.RootElement.TryGetProperty(sectionName, out var section) ||
                section.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var package in section.EnumerateObject())
            {
                if (package.Value.ValueKind != JsonValueKind.Object ||
                    !package.Value.TryGetProperty("version", out var versionElement) ||
                    versionElement.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                AddVersion(versions, package.Name, versionElement.GetString());
            }
        }

        return versions;
    }

    private static IReadOnlyDictionary<string, string> ParseTomlLock(string lockfilePath)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? packageName = null;
        string? packageVersion = null;

        using var reader = new StreamReader(lockfilePath);
        while (reader.ReadLine() is { } rawLine)
        {
            var line = rawLine.Trim();
            if (line.Equals("[[package]]", StringComparison.OrdinalIgnoreCase))
            {
                AddVersion(versions, packageName, packageVersion);
                packageName = null;
                packageVersion = null;
                continue;
            }

            if (TryReadTomlString(line, "name", out var name))
            {
                packageName = name;
            }
            else if (TryReadTomlString(line, "version", out var version))
            {
                packageVersion = version;
            }
        }

        AddVersion(versions, packageName, packageVersion);
        return versions;
    }

    private static bool TryReadTomlString(string line, string key, out string value)
    {
        value = string.Empty;
        var separator = line.IndexOf('=');
        if (separator < 0 ||
            !line[..separator].Trim().Equals(key, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rawValue = line[(separator + 1)..].Trim();
        if (rawValue.Length < 2 ||
            (rawValue[0] != '"' && rawValue[0] != '\'') ||
            rawValue[^1] != rawValue[0])
        {
            return false;
        }

        value = rawValue[1..^1];
        return true;
    }

    private static void AddVersion(IDictionary<string, string> versions, string? packageName, string? version)
    {
        var normalizedVersion = DependencyInventorySupport.NormalizeVersion(version)?.TrimStart('=');
        if (string.IsNullOrWhiteSpace(packageName) || string.IsNullOrWhiteSpace(normalizedVersion))
        {
            return;
        }

        versions[NormalizePackageName(packageName)] = normalizedVersion;
    }

    private static string NormalizePackageName(string packageName)
    {
        var builder = new StringBuilder(packageName.Length);
        var previousWasSeparator = false;
        foreach (var character in packageName.Trim())
        {
            if (character is '-' or '_' or '.')
            {
                if (!previousWasSeparator)
                {
                    builder.Append('-');
                    previousWasSeparator = true;
                }

                continue;
            }

            builder.Append(char.ToLowerInvariant(character));
            previousWasSeparator = false;
        }

        return builder.ToString();
    }
}

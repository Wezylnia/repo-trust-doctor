using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class PnpmLockfileResolver : INpmLockfileResolver
{
    private const long MaximumLockfileBytes = 64L * 1024 * 1024;
    private static readonly HashSet<string> DependencySections = new(StringComparer.OrdinalIgnoreCase)
    {
        "dependencies",
        "devDependencies",
        "optionalDependencies"
    };

    private readonly string lockfileDirectory;
    private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> importerVersions;

    private PnpmLockfileResolver(
        string lockfileDirectory,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> importerVersions)
    {
        this.lockfileDirectory = lockfileDirectory;
        this.importerVersions = importerVersions;
    }

    public string VersionSource => "pnpm-lock";

    public bool TryResolve(
        string manifestDirectory,
        string packageName,
        string? requestedVersion,
        out string version)
    {
        version = string.Empty;
        var importer = NormalizePath(Path.GetRelativePath(lockfileDirectory, manifestDirectory));
        if (importer.StartsWith("../", StringComparison.Ordinal) || importer.Equals("..", StringComparison.Ordinal))
        {
            return false;
        }

        importer = importer.Length == 0 ? "." : importer;
        if (!importerVersions.TryGetValue(importer, out var packages) ||
            !packages.TryGetValue(packageName, out var lockedVersion) ||
            !NpmPackageLockResolver.IsExactVersion(lockedVersion))
        {
            return false;
        }

        version = lockedVersion;
        return true;
    }

    public static bool TryLoad(
        string lockfilePath,
        string relativePath,
        List<string> warnings,
        out PnpmLockfileResolver? resolver)
    {
        resolver = null;
        if (!RepositoryFileSystem.CanReadAsText(lockfilePath, MaximumLockfileBytes))
        {
            warnings.Add(
                $"Skipped pnpm lockfile '{relativePath}' because it exceeds the {MaximumLockfileBytes / (1024 * 1024)} MiB lockfile safety limit or is not readable as text.");
            return false;
        }

        try
        {
            resolver = new PnpmLockfileResolver(
                Path.GetDirectoryName(lockfilePath) ?? string.Empty,
                ParseImporters(lockfilePath));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not read pnpm lockfile '{relativePath}'.");
            return false;
        }
    }

    private static IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> ParseImporters(string lockfilePath)
    {
        var importers = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var inImporters = false;
        var currentImporter = ".";
        var currentSection = string.Empty;
        var currentPackage = string.Empty;
        var currentPackageIndent = -1;

        using var reader = new StreamReader(lockfilePath);
        while (reader.ReadLine() is { } rawLine)
        {
            var line = StripYamlComment(rawLine);
            if (string.IsNullOrWhiteSpace(line) || !TryReadProperty(line, out var indent, out var key, out var value))
            {
                continue;
            }

            if (indent == 0)
            {
                inImporters = key.Equals("importers", StringComparison.OrdinalIgnoreCase);
                currentImporter = ".";
                currentSection = DependencySections.Contains(key) ? key : string.Empty;
                currentPackage = string.Empty;
                if (currentSection.Length > 0)
                {
                    GetImporter(importers, currentImporter);
                }

                continue;
            }

            if (inImporters && indent == 2 && value.Length == 0)
            {
                currentImporter = NormalizePath(Unquote(key));
                currentSection = string.Empty;
                currentPackage = string.Empty;
                GetImporter(importers, currentImporter);
                continue;
            }

            var sectionIndent = inImporters ? 4 : 0;
            var packageIndent = inImporters ? 6 : 2;
            if (indent == sectionIndent && DependencySections.Contains(key))
            {
                currentSection = key;
                currentPackage = string.Empty;
                continue;
            }

            if (currentSection.Length == 0)
            {
                continue;
            }

            if (indent == packageIndent)
            {
                currentPackage = Unquote(key);
                currentPackageIndent = indent;
                AddVersion(importers, currentImporter, currentPackage, value);
                continue;
            }

            if (currentPackage.Length > 0 &&
                indent > currentPackageIndent &&
                key.Equals("version", StringComparison.OrdinalIgnoreCase))
            {
                AddVersion(importers, currentImporter, currentPackage, value);
            }
        }

        return importers.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyDictionary<string, string>)pair.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> GetImporter(
        IDictionary<string, Dictionary<string, string>> importers,
        string importer)
    {
        if (!importers.TryGetValue(importer, out var packages))
        {
            packages = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            importers[importer] = packages;
        }

        return packages;
    }

    private static void AddVersion(
        IDictionary<string, Dictionary<string, string>> importers,
        string importer,
        string packageName,
        string rawVersion)
    {
        var version = NormalizeVersion(rawVersion);
        if (packageName.Length == 0 || !NpmPackageLockResolver.IsExactVersion(version))
        {
            return;
        }

        GetImporter(importers, importer)[packageName] = version;
    }

    private static string NormalizeVersion(string value)
    {
        var version = Unquote(value);
        var peerSuffix = version.IndexOf('(');
        if (peerSuffix >= 0)
        {
            version = version[..peerSuffix];
        }

        return version.Trim();
    }

    private static bool TryReadProperty(string line, out int indent, out string key, out string value)
    {
        indent = line.TakeWhile(character => character == ' ').Count();
        var trimmed = line[indent..];
        var separator = trimmed.IndexOf(':');
        if (separator < 0)
        {
            key = string.Empty;
            value = string.Empty;
            return false;
        }

        key = Unquote(trimmed[..separator].Trim());
        value = trimmed[(separator + 1)..].Trim();
        return key.Length > 0;
    }

    private static string StripYamlComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character is '"' or '\'')
            {
                quote = quote == character ? '\0' : quote == '\0' ? character : quote;
            }
            else if (character == '#' && quote == '\0' && (index == 0 || char.IsWhiteSpace(line[index - 1])))
            {
                return line[..index];
            }
        }

        return line;
    }

    private static string Unquote(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length >= 2 &&
               ((trimmed[0] == '"' && trimmed[^1] == '"') ||
                (trimmed[0] == '\'' && trimmed[^1] == '\''))
            ? trimmed[1..^1]
            : trimmed;
    }

    private static string NormalizePath(string path)
    {
        var normalized = path.Replace('\\', '/').Trim('/');
        return normalized.Length == 0 ? "." : normalized;
    }
}

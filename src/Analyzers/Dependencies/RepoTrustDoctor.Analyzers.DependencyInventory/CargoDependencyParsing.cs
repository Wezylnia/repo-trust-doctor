using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal static partial class CargoDependencyParsing
{
    internal static CargoSection ParseSection(string line)
    {
        var section = line.Trim('[', ']').Trim();

        if (section.StartsWith("workspace.", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.WorkspaceDependencies;
        }

        if (section.Equals("build-dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".build-dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.BuildDependencies;
        }

        if (section.Equals("dev-dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".dev-dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.DevDependencies;
        }

        if (section.Equals("dependencies", StringComparison.OrdinalIgnoreCase) ||
            section.EndsWith(".dependencies", StringComparison.OrdinalIgnoreCase))
        {
            return CargoSection.Dependencies;
        }

        return CargoSection.None;
    }

    internal static bool TryParseDependencyTable(string line, out string crateName, out DependencyScope scope)
    {
        var section = line.Trim('[', ']').Trim();
        crateName = string.Empty;
        scope = DependencyScope.Production;

        if (section.StartsWith("workspace.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (TryReadDependencyTableName(section, "build-dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".build-dependencies.", out crateName))
        {
            scope = DependencyScope.Development;
            return true;
        }

        if (TryReadDependencyTableName(section, "dev-dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".dev-dependencies.", out crateName))
        {
            scope = DependencyScope.Development;
            return true;
        }

        if (TryReadDependencyTableName(section, "dependencies.", out crateName) ||
            TryReadDependencyTableName(section, ".dependencies.", out crateName))
        {
            scope = DependencyScope.Production;
            return true;
        }

        return false;
    }

    internal static bool IsDependencySection(CargoSection section) =>
        section is CargoSection.Dependencies or CargoSection.DevDependencies or CargoSection.BuildDependencies;

    internal static DependencyScope MapSectionToScope(CargoSection section) =>
        section switch
        {
            CargoSection.DevDependencies => DependencyScope.Development,
            CargoSection.BuildDependencies => DependencyScope.Development,
            _ => DependencyScope.Production
        };

    internal static void ParseDependencyTableLine(string line, CargoTableDependency tableDependency)
    {
        var equalsIndex = line.IndexOf('=', StringComparison.Ordinal);
        if (equalsIndex < 0)
        {
            return;
        }

        var key = line[..equalsIndex].Trim();
        var value = line[(equalsIndex + 1)..].Trim().Trim('"');

        if (key.Equals("version", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Version = value;
        }
        else if (key.Equals("git", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Git = value;
        }
        else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Path = value;
        }
        else if (key.Equals("package", StringComparison.OrdinalIgnoreCase))
        {
            tableDependency.Package = value;
        }
        else if (key.Equals("workspace", StringComparison.OrdinalIgnoreCase) &&
                 bool.TryParse(value, out var workspace))
        {
            tableDependency.Workspace = workspace;
        }
    }

    internal static string? ExtractInlineValue(string inlineTable, string key)
    {
        var pattern = $@"\b{Regex.Escape(key)}\s*=\s*""([^""]*)""";
        var match = Regex.Match(inlineTable, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : null;
    }

    internal static bool UsesWorkspaceDependency(string inlineTable) =>
        Regex.IsMatch(
            inlineTable,
            @"\bworkspace\s*=\s*true\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    internal static bool IsDependencyMetadataKey(string crateName) =>
        crateName.Equals("version", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("features", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("default-features", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("optional", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("path", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("git", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("branch", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("tag", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("rev", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("registry", StringComparison.OrdinalIgnoreCase) ||
        crateName.Equals("package", StringComparison.OrdinalIgnoreCase);

    internal static bool IsExactRequirement(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        version.StartsWith('=') &&
        ExactCargoVersionPattern().IsMatch(version[1..].Trim());

    internal static string? NormalizeVersion(string? requirement) =>
        IsExactRequirement(requirement) ? requirement![1..].Trim() : requirement;

    internal static bool IsWorkspaceRoot(string directory)
    {
        var manifestPath = Path.Combine(directory, "Cargo.toml");
        if (!RepositoryFileSystem.CanReadAsText(manifestPath))
        {
            return false;
        }

        try
        {
            return File.ReadAllText(manifestPath).Contains("[workspace]", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static bool IsRepositoryLocalPathDependency(
        string repositoryPath,
        string manifestPath,
        string? dependencyPath)
    {
        if (string.IsNullOrWhiteSpace(dependencyPath))
        {
            return false;
        }

        var normalizedManifestPath = manifestPath.Replace('/', Path.DirectorySeparatorChar);
        var manifestDirectory = Path.GetDirectoryName(Path.Combine(repositoryPath, normalizedManifestPath));
        if (manifestDirectory is null)
        {
            return false;
        }

        var fullDependencyPath = Path.GetFullPath(Path.IsPathRooted(dependencyPath)
            ? dependencyPath
            : Path.Combine(manifestDirectory, dependencyPath));
        return IsSameOrChildPath(fullDependencyPath, Path.GetFullPath(repositoryPath));
    }

    internal static bool IsSameOrChildPath(string path, string parent)
    {
        var normalizedPath = TrimTrailingDirectorySeparators(Path.GetFullPath(path));
        var normalizedParent = TrimTrailingDirectorySeparators(Path.GetFullPath(parent));
        return string.Equals(normalizedPath, normalizedParent, PathComparison) ||
               normalizedPath.StartsWith(EnsureTrailingDirectorySeparator(normalizedParent), PathComparison);
    }

    private static bool TryReadDependencyTableName(string section, string marker, out string crateName)
    {
        crateName = string.Empty;
        var markerIndex = section.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0)
        {
            return false;
        }

        crateName = section[(markerIndex + marker.Length)..].Trim().Trim('"', '\'');
        return crateName.Length > 0 && !crateName.Contains('.', StringComparison.Ordinal);
    }

    private static string EnsureTrailingDirectorySeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;

    private static string TrimTrailingDirectorySeparators(string path)
    {
        var root = Path.GetPathRoot(path) ?? string.Empty;
        while (path.Length > root.Length &&
               (path[^1] == Path.DirectorySeparatorChar || path[^1] == Path.AltDirectorySeparatorChar))
        {
            path = path[..^1];
        }

        return path;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactCargoVersionPattern();
}

internal sealed class CargoTableDependency(string crateName, DependencyScope scope)
{
    public string CrateName { get; } = crateName;

    public DependencyScope Scope { get; } = scope;

    public string? Version { get; set; }

    public string? Git { get; set; }

    public string? Path { get; set; }

    public string? Package { get; set; }

    public bool Workspace { get; set; }
}

internal enum CargoSection
{
    None,
    Dependencies,
    DevDependencies,
    BuildDependencies,
    WorkspaceDependencies
}

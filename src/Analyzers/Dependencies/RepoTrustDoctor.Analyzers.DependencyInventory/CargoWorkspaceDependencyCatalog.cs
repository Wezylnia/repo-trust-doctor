using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed record CargoWorkspaceDependency(
    string Value,
    string DefinitionPath);

internal sealed class CargoWorkspaceDependencyCatalog
{
    private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, CargoWorkspaceDependency>> workspaces;

    private CargoWorkspaceDependencyCatalog(
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, CargoWorkspaceDependency>> workspaces)
    {
        this.workspaces = workspaces;
    }

    public static CargoWorkspaceDependencyCatalog Create(
        AnalysisContext context,
        IReadOnlyCollection<string> manifestPaths,
        List<string> warnings)
    {
        var workspaces = new Dictionary<string, IReadOnlyDictionary<string, CargoWorkspaceDependency>>(
            PathComparer);
        foreach (var manifestPath in manifestPaths)
        {
            var relativePath = DependencyInventorySupport.Relative(context, manifestPath);
            if (!DependencyInventorySupport.TryReadText(manifestPath, out var content, warnings, relativePath) ||
                !content.Contains("[workspace]", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var definitions = ReadDefinitions(content, relativePath);
            if (definitions.Count > 0)
            {
                workspaces[Path.GetDirectoryName(manifestPath)!] = definitions;
            }
        }

        return new CargoWorkspaceDependencyCatalog(workspaces);
    }

    public bool TryResolve(string manifestPath, string alias, out CargoWorkspaceDependency dependency)
    {
        dependency = default!;
        var manifestDirectory = Path.GetDirectoryName(manifestPath);
        if (manifestDirectory is null)
        {
            return false;
        }

        var workspace = workspaces
            .Where(item => CargoDependencyParsing.IsSameOrChildPath(manifestDirectory, item.Key))
            .OrderByDescending(item => item.Key.Length)
            .FirstOrDefault();
        if (workspace.Value is null ||
            !workspace.Value.TryGetValue(alias, out var resolved))
        {
            return false;
        }

        dependency = resolved;
        return true;
    }

    private static IReadOnlyDictionary<string, CargoWorkspaceDependency> ReadDefinitions(
        string content,
        string relativePath)
    {
        var definitions = new Dictionary<string, CargoWorkspaceDependency>(StringComparer.OrdinalIgnoreCase);
        var inWorkspaceDependencies = false;
        CargoTableDependency? tableDependency = null;

        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                AddTableDefinition(definitions, tableDependency, relativePath);
                tableDependency = null;
                var section = line.Trim('[', ']').Trim();
                inWorkspaceDependencies = section.Equals(
                    "workspace.dependencies",
                    StringComparison.OrdinalIgnoreCase);
                const string tablePrefix = "workspace.dependencies.";
                if (section.StartsWith(tablePrefix, StringComparison.OrdinalIgnoreCase))
                {
                    var tableAlias = section[tablePrefix.Length..].Trim().Trim('"', '\'');
                    tableDependency = tableAlias.Length == 0
                        ? null
                        : new CargoTableDependency(tableAlias, DependencyScope.Production);
                }

                continue;
            }

            if (tableDependency is not null)
            {
                CargoDependencyParsing.ParseDependencyTableLine(line, tableDependency);
                continue;
            }

            if (!inWorkspaceDependencies)
            {
                continue;
            }

            var equalsIndex = line.IndexOf('=', StringComparison.Ordinal);
            if (equalsIndex <= 0)
            {
                continue;
            }

            var alias = line[..equalsIndex].Trim().Trim('"', '\'');
            var value = line[(equalsIndex + 1)..].Trim();
            if (alias.Length > 0 && value.Length > 0)
            {
                definitions[alias] = new CargoWorkspaceDependency(
                    NormalizeDefinition(value),
                    relativePath);
            }
        }

        AddTableDefinition(definitions, tableDependency, relativePath);
        return definitions;
    }

    private static void AddTableDefinition(
        IDictionary<string, CargoWorkspaceDependency> definitions,
        CargoTableDependency? dependency,
        string relativePath)
    {
        if (dependency is null)
        {
            return;
        }

        var properties = new List<string>();
        AddProperty(properties, "version", dependency.Version);
        AddProperty(properties, "git", dependency.Git);
        AddProperty(properties, "path", dependency.Path);
        AddProperty(properties, "package", dependency.Package);
        if (properties.Count > 0)
        {
            definitions[dependency.CrateName] = new CargoWorkspaceDependency(
                "{ " + string.Join(", ", properties) + " }",
                relativePath);
        }
    }

    private static void AddProperty(ICollection<string> properties, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            properties.Add($"{name} = \"{value}\"");
        }
    }

    private static string NormalizeDefinition(string value)
    {
        if (value.StartsWith('{'))
        {
            return value;
        }

        var commentIndex = value.IndexOf(" #", StringComparison.Ordinal);
        var version = (commentIndex >= 0 ? value[..commentIndex] : value).Trim().Trim('"', '\'');
        return $"{{ version = \"{version}\" }}";
    }

    private static StringComparer PathComparer =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}

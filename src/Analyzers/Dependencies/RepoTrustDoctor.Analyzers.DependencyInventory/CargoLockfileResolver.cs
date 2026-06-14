namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class CargoLockfileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private CargoLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static CargoLockfileResolver? TryCreate(
        string lockfilePath,
        string relativePath,
        DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(
                lockfilePath,
                out var content,
                state.Warnings,
                relativePath))
        {
            return null;
        }

        var candidates = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        string? name = null;
        string? version = null;
        string? source = null;
        foreach (var rawLine in DependencyInventorySupport.SplitLines(content))
        {
            var line = rawLine.Trim();
            if (line.Equals("[[package]]", StringComparison.Ordinal))
            {
                AddRegistryPackage(candidates, name, version, source);
                name = null;
                version = null;
                source = null;
                continue;
            }

            if (TryReadStringProperty(line, "name", out var nameValue))
            {
                name = nameValue;
            }
            else if (TryReadStringProperty(line, "version", out var versionValue))
            {
                version = versionValue;
            }
            else if (TryReadStringProperty(line, "source", out var sourceValue))
            {
                source = sourceValue;
            }
        }

        AddRegistryPackage(candidates, name, version, source);
        var versions = candidates
            .Where(entry => entry.Value.Count == 1)
            .ToDictionary(
                entry => entry.Key,
                entry => entry.Value.Single(),
                StringComparer.OrdinalIgnoreCase);
        return new CargoLockfileResolver(relativePath, versions);
    }

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(packageName, out version!);

    private static void AddRegistryPackage(
        IDictionary<string, HashSet<string>> candidates,
        string? name,
        string? version,
        string? source)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            string.IsNullOrWhiteSpace(version) ||
            source?.StartsWith("registry+", StringComparison.OrdinalIgnoreCase) != true)
        {
            return;
        }

        if (!candidates.TryGetValue(name, out var packageVersions))
        {
            packageVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            candidates[name] = packageVersions;
        }

        packageVersions.Add(version);
    }

    private static bool TryReadStringProperty(string line, string propertyName, out string value)
    {
        value = string.Empty;
        var prefix = propertyName + " = ";
        if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        value = line[prefix.Length..].Trim().Trim('"');
        return value.Length > 0;
    }
}

using System.Text.Json;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class ComposerLockfileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private ComposerLockfileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static ComposerLockfileResolver? TryCreate(
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

        try
        {
            using var document = JsonDocument.Parse(content);
            var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ReadPackageSection(document.RootElement, "packages", versions);
            ReadPackageSection(document.RootElement, "packages-dev", versions);
            return new ComposerLockfileResolver(relativePath, versions);
        }
        catch (JsonException ex)
        {
            state.Warnings.Add($"Could not parse composer lockfile '{relativePath}': {ex.Message}");
            return null;
        }
    }

    public bool TryResolve(string packageName, out string version) =>
        versions.TryGetValue(packageName, out version!);

    private static void ReadPackageSection(
        JsonElement root,
        string propertyName,
        IDictionary<string, string> versions)
    {
        if (!root.TryGetProperty(propertyName, out var packages) ||
            packages.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var package in packages.EnumerateArray())
        {
            if (!TryGetString(package, "name", out var name) ||
                !TryGetString(package, "version", out var version))
            {
                continue;
            }

            versions[name] = version;
        }
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }
}

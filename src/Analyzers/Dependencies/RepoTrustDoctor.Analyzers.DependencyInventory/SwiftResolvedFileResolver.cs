using System.Text.Json;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed class SwiftResolvedFileResolver
{
    private readonly IReadOnlyDictionary<string, string> versions;

    private SwiftResolvedFileResolver(string relativePath, IReadOnlyDictionary<string, string> versions)
    {
        RelativePath = relativePath;
        this.versions = versions;
    }

    public string RelativePath { get; }

    public static SwiftResolvedFileResolver? TryCreate(
        string resolvedFilePath,
        string relativePath,
        DependencyInventoryState state)
    {
        if (!DependencyInventorySupport.TryReadText(
                resolvedFilePath,
                out var content,
                state.Warnings,
                relativePath))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;
            var pins = root.TryGetProperty("pins", out var currentPins)
                ? currentPins
                : root.TryGetProperty("object", out var objectNode) &&
                  objectNode.TryGetProperty("pins", out var legacyPins)
                    ? legacyPins
                    : default;
            if (pins.ValueKind != JsonValueKind.Array)
            {
                return new SwiftResolvedFileResolver(
                    relativePath,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            }

            var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var pin in pins.EnumerateArray())
            {
                if (!pin.TryGetProperty("state", out var stateNode) ||
                    !TryGetString(stateNode, "version", out var version))
                {
                    continue;
                }

                AddIdentity(pin, "identity", version, versions);
                AddIdentity(pin, "package", version, versions);
                AddLocation(pin, "location", version, versions);
                AddLocation(pin, "repositoryURL", version, versions);
            }

            return new SwiftResolvedFileResolver(relativePath, versions);
        }
        catch (JsonException ex)
        {
            state.Warnings.Add($"Could not parse Swift resolved file '{relativePath}': {ex.Message}");
            return null;
        }
    }

    public bool TryResolve(string packageReference, out string version) =>
        versions.TryGetValue(NormalizeIdentity(packageReference), out version!);

    private static void AddIdentity(
        JsonElement pin,
        string propertyName,
        string version,
        IDictionary<string, string> versions)
    {
        if (TryGetString(pin, propertyName, out var identity))
        {
            versions[NormalizeIdentity(identity)] = version;
        }
    }

    private static void AddLocation(
        JsonElement pin,
        string propertyName,
        string version,
        IDictionary<string, string> versions)
    {
        if (!TryGetString(pin, propertyName, out var location))
        {
            return;
        }

        versions[NormalizeIdentity(location)] = version;
        var lastSegment = location.TrimEnd('/').Split('/').LastOrDefault();
        if (!string.IsNullOrWhiteSpace(lastSegment))
        {
            versions[NormalizeIdentity(lastSegment)] = version;
        }
    }

    private static string NormalizeIdentity(string value)
    {
        var normalized = value.Trim().TrimEnd('/');
        if (normalized.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^4];
        }

        return normalized.ToLowerInvariant();
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

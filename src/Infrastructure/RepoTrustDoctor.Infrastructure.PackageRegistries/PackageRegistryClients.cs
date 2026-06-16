using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public interface IPackageMetadataClient
{
    DependencyEcosystem Ecosystem { get; }

    Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken);
}

public sealed class NuGetPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.NuGet;

    public async Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var id = Uri.EscapeDataString(package.Name.ToLowerInvariant());
        var uri = new Uri($"https://api.nuget.org/v3/registration5-gz-semver2/{id}/index.json");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        if (!result.Success)
        {
            return PackageMetadataLookupResult.FromSafeLookupFailure(result);
        }

        if (result.Body is null)
        {
            return PackageMetadataLookup.InvalidResponse("NuGet registry returned an empty response.");
        }

        return PackageMetadataLookup.Parse(
            () => PackageMetadataParser.ParseNuGet(package, result.Body),
            "NuGet registry returned metadata without package versions.");
    }
}

public sealed class NpmPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Npm;

    public async Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var name = Uri.EscapeDataString(package.Name);
        var uri = new Uri($"https://registry.npmjs.org/{name}");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        if (!result.Success)
        {
            return PackageMetadataLookupResult.FromSafeLookupFailure(result);
        }

        if (result.Body is null)
        {
            return PackageMetadataLookup.InvalidResponse("npm registry returned an empty response.");
        }

        return PackageMetadataLookup.Parse(
            () => PackageMetadataParser.ParseNpm(package, result.Body),
            "npm registry returned metadata without package versions.");
    }
}

public sealed class PyPiPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Python;

    public async Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var name = Uri.EscapeDataString(package.Name);
        var latestUri = new Uri($"https://pypi.org/pypi/{name}/json");
        var latestResult = await lookup.GetStringAsync(latestUri, cancellationToken);
        if (!latestResult.Success)
        {
            return PackageMetadataLookupResult.FromSafeLookupFailure(latestResult);
        }

        if (latestResult.Body is null)
        {
            return PackageMetadataLookup.InvalidResponse("PyPI returned an empty response.");
        }

        string? latestVersion;
        try
        {
            latestVersion = PackageMetadataParser.ReadPyPiVersion(latestResult.Body);
        }
        catch (JsonException ex)
        {
            return PackageMetadataLookup.InvalidResponse(ex.Message);
        }

        if (string.IsNullOrWhiteSpace(latestVersion))
        {
            return PackageMetadataLookup.InvalidResponse("PyPI returned metadata without a latest version.");
        }

        if (string.Equals(latestVersion, package.Version, StringComparison.OrdinalIgnoreCase))
        {
            return PackageMetadataLookup.Parse(
                () => PackageMetadataParser.ParsePyPi(package, latestResult.Body, latestResult.Body),
                "PyPI returned incomplete package metadata.");
        }

        var requestedUri = new Uri($"https://pypi.org/pypi/{name}/{Uri.EscapeDataString(package.Version!)}/json");
        var requestedResult = await lookup.GetStringAsync(requestedUri, cancellationToken);
        if (!requestedResult.Success &&
            requestedResult.ErrorKind is not SafeLookupErrorKind.NotFound)
        {
            return PackageMetadataLookupResult.FromSafeLookupFailure(requestedResult);
        }

        return PackageMetadataLookup.Parse(
            () => PackageMetadataParser.ParsePyPi(
                package,
                latestResult.Body,
                requestedResult.Success ? requestedResult.Body : null),
            "PyPI returned incomplete package metadata.");
    }
}

public sealed class MavenCentralPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Maven;

    public async Task<PackageMetadataLookupResult> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        var coordinates = package.Name.Split(':', 2);
        if (coordinates.Length != 2)
        {
            return PackageMetadataLookup.InvalidResponse("Maven package coordinates must use the 'group:artifact' form.");
        }

        var group = Uri.EscapeDataString(coordinates[0]);
        var artifact = Uri.EscapeDataString(coordinates[1]);
        var uri = new Uri($"https://search.maven.org/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22&rows=1&wt=json");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        if (!result.Success)
        {
            return PackageMetadataLookupResult.FromSafeLookupFailure(result);
        }

        if (result.Body is null)
        {
            return PackageMetadataLookup.InvalidResponse("Maven Central returned an empty response.");
        }

        try
        {
            var metadata = PackageMetadataParser.ParseMavenCentral(package, result.Body);
            return metadata is null
                ? PackageMetadataLookupResult.NotFound("Maven Central returned no matching package.")
                : PackageMetadataLookupResult.Found(metadata);
        }
        catch (JsonException ex)
        {
            return PackageMetadataLookup.InvalidResponse(ex.Message);
        }
    }
}

internal static class PackageMetadataLookup
{
    public static PackageMetadataLookupResult Parse(
        Func<PackageRegistryMetadata?> parser,
        string missingMetadataMessage)
    {
        try
        {
            var metadata = parser();
            return metadata is null
                ? InvalidResponse(missingMetadataMessage)
                : PackageMetadataLookupResult.Found(metadata);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            return InvalidResponse(ex.Message);
        }
    }

    public static PackageMetadataLookupResult InvalidResponse(string message) =>
        PackageMetadataLookupResult.Failure(
            PackageMetadataLookupStatus.InvalidResponse,
            SafeLookupErrorKind.MalformedResponse,
            message);
}

public static class PackageMetadataParser
{
    public static PackageRegistryMetadata? ParseNuGet(DependencyPackageInfo package, string json)
    {
        using var document = JsonDocument.Parse(json);
        var versions = new List<JsonElement>();
        CollectCatalogEntries(document.RootElement, versions);
        if (versions.Count == 0)
        {
            return null;
        }

        var latest = versions
            .Select(entry => new { Entry = entry, Version = ReadString(entry, "version") })
            .Where(item => !string.IsNullOrWhiteSpace(item.Version))
            .OrderBy(item => item.Version, NuGetVersionStringComparer.Instance)
            .Last();

        var requested = versions.FirstOrDefault(entry =>
            string.Equals(ReadString(entry, "version"), package.Version, StringComparison.OrdinalIgnoreCase));
        var requestedVersionMatched = requested.ValueKind == JsonValueKind.Object;
        var selected = requestedVersionMatched ? requested : default;

        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest.Version,
            ReadDate(selected, "published"),
            selected.ValueKind == JsonValueKind.Object &&
                selected.TryGetProperty("deprecation", out _),
            false,
            ReadString(selected, "repositoryUrl"),
            ReadString(selected, "projectUrl"),
            ReadString(selected, "licenseExpression") ?? ReadString(selected, "licenseUrl"),
            null,
            "nuget.org",
            BuildPackageMetadata(package, requestedVersionMatched));
    }

    public static PackageRegistryMetadata? ParseNpm(DependencyPackageInfo package, string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var latest = root.TryGetProperty("dist-tags", out var tags) ? ReadString(tags, "latest") : null;
        JsonElement latestVersionElement = default;
        JsonElement requestedVersionElement = default;
        if (!string.IsNullOrWhiteSpace(latest) &&
            root.TryGetProperty("versions", out var versions) &&
            versions.ValueKind == JsonValueKind.Object &&
            versions.TryGetProperty(latest, out var latestElement))
        {
            latestVersionElement = latestElement;
        }

        if (root.TryGetProperty("versions", out versions) &&
            versions.ValueKind == JsonValueKind.Object &&
            !string.IsNullOrWhiteSpace(package.Version))
        {
            versions.TryGetProperty(package.Version, out requestedVersionElement);
        }

        if (latestVersionElement.ValueKind == JsonValueKind.Undefined &&
            versions.ValueKind == JsonValueKind.Object)
        {
            latestVersionElement = versions.EnumerateObject().LastOrDefault().Value;
        }

        if (latestVersionElement.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

        var repositoryUrl = ReadString(requestedVersionElement, "repository");
        if (requestedVersionElement.ValueKind == JsonValueKind.Object &&
            requestedVersionElement.TryGetProperty("repository", out var repository) &&
            repository.ValueKind == JsonValueKind.Object)
        {
            repositoryUrl = ReadString(repository, "url");
        }

        DateTimeOffset? publishedAt = null;
        if (!string.IsNullOrWhiteSpace(package.Version) &&
            root.TryGetProperty("time", out var time))
        {
            publishedAt = ReadDate(time, package.Version);
        }

        var metadata = BuildPackageMetadata(package, requestedVersionElement.ValueKind == JsonValueKind.Object);
        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest ?? ReadString(latestVersionElement, "version"),
            publishedAt,
            !string.IsNullOrWhiteSpace(ReadString(requestedVersionElement, "deprecated")),
            false,
            repositoryUrl,
            ReadString(requestedVersionElement, "homepage"),
            ReadString(requestedVersionElement, "license"),
            null,
            "registry.npmjs.org",
            metadata);
    }

    public static string? ReadPyPiVersion(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty("info", out var info)
            ? ReadString(info, "version")
            : null;
    }

    public static PackageRegistryMetadata? ParsePyPi(
        DependencyPackageInfo package,
        string latestJson,
        string? requestedVersionJson = null)
    {
        using var latestDocument = JsonDocument.Parse(latestJson);
        var latestRoot = latestDocument.RootElement;
        if (!latestRoot.TryGetProperty("info", out var latestInfo))
        {
            return null;
        }

        var latest = ReadString(latestInfo, "version");
        using var requestedDocument = !string.IsNullOrWhiteSpace(requestedVersionJson)
            ? JsonDocument.Parse(requestedVersionJson)
            : null;
        JsonElement requestedRoot = default;
        JsonElement requestedInfo = default;
        if (requestedDocument is not null)
        {
            requestedRoot = requestedDocument.RootElement;
            if (requestedRoot.TryGetProperty("info", out var info) &&
                string.Equals(ReadString(info, "version"), package.Version, StringComparison.OrdinalIgnoreCase))
            {
                requestedInfo = info;
            }
        }

        DateTimeOffset? publishedAt = null;
        var yanked = false;
        var releaseArray = FindPyPiReleaseFiles(
            requestedRoot.ValueKind == JsonValueKind.Object ? requestedRoot : latestRoot,
            package.Version);
        if (releaseArray.ValueKind == JsonValueKind.Array && releaseArray.GetArrayLength() > 0)
        {
            var release = releaseArray[0];
            publishedAt = ReadDate(release, "upload_time_iso_8601") ?? ReadDate(release, "upload_time");
            yanked = releaseArray.EnumerateArray().All(file =>
                file.TryGetProperty("yanked", out var yankedElement) &&
                yankedElement.ValueKind == JsonValueKind.True);
        }

        string? repositoryUrl = null;
        if (requestedInfo.ValueKind == JsonValueKind.Object &&
            requestedInfo.TryGetProperty("project_urls", out var urls) &&
            urls.ValueKind == JsonValueKind.Object)
        {
            repositoryUrl = ReadString(urls, "Source") ?? ReadString(urls, "Repository") ?? ReadString(urls, "Source Code");
        }

        var metadata = BuildPackageMetadata(package, requestedInfo.ValueKind == JsonValueKind.Object);
        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest,
            publishedAt,
            yanked,
            yanked,
            repositoryUrl,
            ReadString(requestedInfo, "home_page"),
            ReadString(requestedInfo, "license_expression") ?? ReadString(requestedInfo, "license"),
            null,
            "pypi.org",
            metadata);
    }

    public static PackageRegistryMetadata? ParseMavenCentral(DependencyPackageInfo package, string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("response", out var response) ||
            !response.TryGetProperty("docs", out var docs) ||
            docs.ValueKind != JsonValueKind.Array ||
            docs.GetArrayLength() == 0)
        {
            return null;
        }

        var doc = docs[0];
        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            ReadString(doc, "latestVersion"),
            ReadUnixMillis(doc, "timestamp"),
            false,
            false,
            null,
            null,
            null,
            null,
            "search.maven.org",
            BuildPackageMetadata(package));
    }

    private static IReadOnlyDictionary<string, string> BuildPackageMetadata(
        DependencyPackageInfo package,
        bool requestedVersionMatched = true) =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["scope"] = package.Scope.ToString(),
            ["isDirect"] = package.IsDirect.ToString(),
            ["requestedVersionMatched"] = requestedVersionMatched.ToString()
        };

    private static JsonElement FindPyPiReleaseFiles(JsonElement root, string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return default;
        }

        if (root.TryGetProperty("releases", out var releases) &&
            releases.ValueKind == JsonValueKind.Object &&
            releases.TryGetProperty(version, out var releaseArray))
        {
            return releaseArray;
        }

        return root.TryGetProperty("urls", out var urls) && urls.ValueKind == JsonValueKind.Array
            ? urls
            : default;
    }

    private static void CollectCatalogEntries(JsonElement element, List<JsonElement> entries)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("catalogEntry", out var catalogEntry))
            {
                entries.Add(catalogEntry);
            }

            foreach (var property in element.EnumerateObject())
            {
                CollectCatalogEntries(property.Value, entries);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                CollectCatalogEntries(item, entries);
            }
        }
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
    }

    private static DateTimeOffset? ReadDate(JsonElement element, string propertyName)
    {
        var value = ReadString(element, propertyName);
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;
    }

    private static DateTimeOffset? ReadUnixMillis(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return property.TryGetInt64(out var millis) ? DateTimeOffset.FromUnixTimeMilliseconds(millis) : null;
    }
}

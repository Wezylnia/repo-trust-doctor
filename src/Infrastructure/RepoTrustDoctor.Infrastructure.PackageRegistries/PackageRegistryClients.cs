using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public interface IPackageMetadataClient
{
    DependencyEcosystem Ecosystem { get; }

    Task<PackageRegistryMetadata?> GetMetadataAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken);
}

public sealed class NuGetPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.NuGet;

    public async Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken)
    {
        var id = Uri.EscapeDataString(package.Name.ToLowerInvariant());
        var uri = new Uri($"https://api.nuget.org/v3/registration5-gz-semver2/{id}/index.json");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        return result.Success && result.Body is not null
            ? PackageMetadataParser.ParseNuGet(package, result.Body)
            : null;
    }
}

public sealed class NpmPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Npm;

    public async Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken)
    {
        var name = Uri.EscapeDataString(package.Name);
        var uri = new Uri($"https://registry.npmjs.org/{name}");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        return result.Success && result.Body is not null
            ? PackageMetadataParser.ParseNpm(package, result.Body)
            : null;
    }
}

public sealed class PyPiPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Python;

    public async Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken)
    {
        var name = Uri.EscapeDataString(package.Name);
        var uri = new Uri($"https://pypi.org/pypi/{name}/json");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        return result.Success && result.Body is not null
            ? PackageMetadataParser.ParsePyPi(package, result.Body)
            : null;
    }
}

public sealed class MavenCentralPackageMetadataClient(SafeHttpLookup lookup) : IPackageMetadataClient
{
    public DependencyEcosystem Ecosystem => DependencyEcosystem.Maven;

    public async Task<PackageRegistryMetadata?> GetMetadataAsync(DependencyPackageInfo package, CancellationToken cancellationToken)
    {
        var coordinates = package.Name.Split(':', 2);
        if (coordinates.Length != 2)
        {
            return null;
        }

        var group = Uri.EscapeDataString(coordinates[0]);
        var artifact = Uri.EscapeDataString(coordinates[1]);
        var uri = new Uri($"https://search.maven.org/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22&rows=1&wt=json");
        var result = await lookup.GetStringAsync(uri, cancellationToken);
        return result.Success && result.Body is not null
            ? PackageMetadataParser.ParseMavenCentral(package, result.Body)
            : null;
    }
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
        var selected = requested.ValueKind == JsonValueKind.Undefined ? latest.Entry : requested;

        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest.Version,
            ReadDate(selected, "published"),
            selected.TryGetProperty("deprecation", out _),
            false,
            ReadString(selected, "repositoryUrl"),
            ReadString(selected, "projectUrl"),
            ReadString(selected, "licenseExpression") ?? ReadString(selected, "licenseUrl"),
            null,
            "nuget.org",
            BuildPackageMetadata(package));
    }

    public static PackageRegistryMetadata? ParseNpm(DependencyPackageInfo package, string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var latest = root.TryGetProperty("dist-tags", out var tags) ? ReadString(tags, "latest") : null;
        JsonElement versionElement = default;
        if (!string.IsNullOrWhiteSpace(latest) &&
            root.TryGetProperty("versions", out var versions) &&
            versions.ValueKind == JsonValueKind.Object &&
            versions.TryGetProperty(latest, out var latestElement))
        {
            versionElement = latestElement;
        }

        if (versionElement.ValueKind == JsonValueKind.Undefined && root.TryGetProperty("versions", out versions))
        {
            versionElement = versions.EnumerateObject().LastOrDefault().Value;
        }

        if (versionElement.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

        var repositoryUrl = ReadString(versionElement, "repository");
        if (versionElement.TryGetProperty("repository", out var repository) &&
            repository.ValueKind == JsonValueKind.Object)
        {
            repositoryUrl = ReadString(repository, "url");
        }

        DateTimeOffset? publishedAt = null;
        if (!string.IsNullOrWhiteSpace(latest) &&
            root.TryGetProperty("time", out var time))
        {
            publishedAt = ReadDate(time, latest);
        }

        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest ?? ReadString(versionElement, "version"),
            publishedAt,
            !string.IsNullOrWhiteSpace(ReadString(versionElement, "deprecated")),
            false,
            repositoryUrl,
            ReadString(versionElement, "homepage"),
            ReadString(versionElement, "license"),
            null,
            "registry.npmjs.org",
            BuildPackageMetadata(package));
    }

    public static PackageRegistryMetadata? ParsePyPi(DependencyPackageInfo package, string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (!root.TryGetProperty("info", out var info))
        {
            return null;
        }

        var latest = ReadString(info, "version");
        DateTimeOffset? publishedAt = null;
        var yanked = false;
        if (!string.IsNullOrWhiteSpace(latest) &&
            root.TryGetProperty("releases", out var releases) &&
            releases.TryGetProperty(latest, out var releaseArray) &&
            releaseArray.ValueKind == JsonValueKind.Array &&
            releaseArray.GetArrayLength() > 0)
        {
            var release = releaseArray[0];
            publishedAt = ReadDate(release, "upload_time_iso_8601") ?? ReadDate(release, "upload_time");
            yanked = release.TryGetProperty("yanked", out var yankedElement) && yankedElement.ValueKind == JsonValueKind.True;
        }

        string? repositoryUrl = null;
        if (info.TryGetProperty("project_urls", out var urls) && urls.ValueKind == JsonValueKind.Object)
        {
            repositoryUrl = ReadString(urls, "Source") ?? ReadString(urls, "Repository") ?? ReadString(urls, "Source Code");
        }

        return new PackageRegistryMetadata(
            package.Ecosystem,
            package.Name,
            package.Version,
            latest,
            publishedAt,
            yanked,
            yanked,
            repositoryUrl,
            ReadString(info, "home_page"),
            ReadString(info, "license_expression") ?? ReadString(info, "license"),
            null,
            "pypi.org",
            BuildPackageMetadata(package));
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

    private static IReadOnlyDictionary<string, string> BuildPackageMetadata(DependencyPackageInfo package) =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["scope"] = package.Scope.ToString(),
            ["isDirect"] = package.IsDirect.ToString()
        };

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
        if (!element.TryGetProperty(propertyName, out var property))
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

public static class PackageLicenseNormalizer
{
    private const int MaxExpressionLength = 120;

    public static NormalizedPackageLicense Normalize(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression.Length > MaxExpressionLength)
        {
            return new NormalizedPackageLicense(PackageLicenseFamily.Unknown, null, Truncate(expression), false, false);
        }

        var normalized = expression.Trim();
        var upper = normalized.ToUpperInvariant();
        var spdx = upper
            .Replace("APACHE 2.0", "APACHE-2.0", StringComparison.Ordinal)
            .Replace("BSD 2-CLAUSE", "BSD-2-CLAUSE", StringComparison.Ordinal)
            .Replace("BSD 3-CLAUSE", "BSD-3-CLAUSE", StringComparison.Ordinal);

        foreach (var id in new[] { "MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC" })
        {
            if (spdx.Contains(id, StringComparison.Ordinal))
            {
                return new NormalizedPackageLicense(PackageLicenseFamily.Permissive, id, normalized, true, false);
            }
        }

        foreach (var id in new[] { "AGPL", "LGPL", "GPL" })
        {
            if (spdx.Contains(id, StringComparison.Ordinal))
            {
                return new NormalizedPackageLicense(PackageLicenseFamily.Copyleft, id, normalized, true, true);
            }
        }

        return new NormalizedPackageLicense(PackageLicenseFamily.Unknown, null, normalized, false, false);
    }

    private static string? Truncate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= MaxExpressionLength ? value : value[..MaxExpressionLength];
    }
}

using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

internal enum OsvVersionMatch
{
    NotAffected,
    Affected,
    Indeterminate
}

internal static class OsvAffectedVersionMatcher
{
    public static OsvVersionMatch Match(
        JsonElement advisory,
        DependencyPackageInfo package)
    {
        if (string.IsNullOrWhiteSpace(package.Version) ||
            !advisory.TryGetProperty("affected", out var affected) ||
            affected.ValueKind != JsonValueKind.Array)
        {
            return OsvVersionMatch.Indeterminate;
        }

        var sawIndeterminate = false;
        foreach (var item in affected.EnumerateArray())
        {
            if (!MatchesPackage(item, package))
            {
                continue;
            }

            var result = MatchAffectedItem(item, package.Version);
            if (result == OsvVersionMatch.Affected)
            {
                return result;
            }

            sawIndeterminate |= result == OsvVersionMatch.Indeterminate;
        }

        return sawIndeterminate
            ? OsvVersionMatch.Indeterminate
            : OsvVersionMatch.NotAffected;
    }

    private static OsvVersionMatch MatchAffectedItem(
        JsonElement affected,
        string version)
    {
        var hasExplicitVersions = affected.TryGetProperty("versions", out var versions) &&
                                  versions.ValueKind == JsonValueKind.Array;
        if (hasExplicitVersions &&
            versions.EnumerateArray().Any(item =>
                item.ValueKind == JsonValueKind.String &&
                VersionsEqual(item.GetString(), version)))
        {
            return OsvVersionMatch.Affected;
        }

        if (!affected.TryGetProperty("ranges", out var ranges) ||
            ranges.ValueKind != JsonValueKind.Array)
        {
            return hasExplicitVersions
                ? OsvVersionMatch.NotAffected
                : OsvVersionMatch.Indeterminate;
        }

        var sawIndeterminate = false;
        foreach (var range in ranges.EnumerateArray())
        {
            var result = MatchRange(range, version);
            if (result == OsvVersionMatch.Affected)
            {
                return result;
            }

            sawIndeterminate |= result == OsvVersionMatch.Indeterminate;
        }

        return sawIndeterminate
            ? OsvVersionMatch.Indeterminate
            : OsvVersionMatch.NotAffected;
    }

    private static OsvVersionMatch MatchRange(JsonElement range, string version)
    {
        var type = ReadString(range, "type");
        if (type != "SEMVER" ||
            !range.TryGetProperty("events", out var events) ||
            events.ValueKind != JsonValueKind.Array ||
            !OsvSemanticVersion.TryParse(version, out var target))
        {
            return OsvVersionMatch.Indeterminate;
        }

        var affected = false;
        foreach (var @event in events.EnumerateArray())
        {
            if (ReadString(@event, "introduced") is { } introduced)
            {
                if (introduced == "0")
                {
                    affected = true;
                    continue;
                }

                if (!OsvSemanticVersion.TryParse(introduced, out var boundary))
                {
                    return OsvVersionMatch.Indeterminate;
                }

                if (target.CompareTo(boundary) >= 0)
                {
                    affected = true;
                }
            }
            else if (ReadString(@event, "fixed") is { } fixedVersion)
            {
                if (!OsvSemanticVersion.TryParse(fixedVersion, out var boundary))
                {
                    return OsvVersionMatch.Indeterminate;
                }

                if (target.CompareTo(boundary) >= 0)
                {
                    affected = false;
                }
            }
            else if (ReadString(@event, "limit") is { } limitVersion)
            {
                if (!OsvSemanticVersion.TryParse(limitVersion, out var boundary))
                {
                    return OsvVersionMatch.Indeterminate;
                }

                if (target.CompareTo(boundary) >= 0)
                {
                    affected = false;
                }
            }
            else if (ReadString(@event, "last_affected") is { } lastAffected)
            {
                if (!OsvSemanticVersion.TryParse(lastAffected, out var boundary))
                {
                    return OsvVersionMatch.Indeterminate;
                }

                if (target.CompareTo(boundary) > 0)
                {
                    affected = false;
                }
            }
        }

        return affected ? OsvVersionMatch.Affected : OsvVersionMatch.NotAffected;
    }

    private static bool MatchesPackage(
        JsonElement affected,
        DependencyPackageInfo package)
    {
        if (!affected.TryGetProperty("package", out var packageElement) ||
            packageElement.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var expectedEcosystem = OsvEcosystemNames.GetName(package.Ecosystem);
        return string.Equals(
                   ReadString(packageElement, "ecosystem"),
                   expectedEcosystem,
                   StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   NormalizePackageName(expectedEcosystem, ReadString(packageElement, "name")),
                   NormalizePackageName(expectedEcosystem, package.Name),
                   PackageNameComparison(expectedEcosystem));
    }

    private static string? NormalizePackageName(string? ecosystem, string? packageName)
    {
        if (packageName is null)
        {
            return null;
        }

        return ecosystem?.Equals("PyPI", StringComparison.OrdinalIgnoreCase) == true
            ? SqliteOsvAdvisoryStore.NormalizePackageName(ecosystem, packageName)
            : packageName.Trim();
    }

    private static StringComparison PackageNameComparison(string? ecosystem) =>
        ecosystem is "Go" or "Maven" or "SwiftURL"
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;

    private static bool VersionsEqual(string? left, string right)
    {
        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return OsvSemanticVersion.TryParse(left, out var leftVersion) &&
               OsvSemanticVersion.TryParse(right, out var rightVersion) &&
               leftVersion.CompareTo(rightVersion) == 0;
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}

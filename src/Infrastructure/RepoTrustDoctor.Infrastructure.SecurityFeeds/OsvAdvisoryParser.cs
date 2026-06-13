using System.Globalization;
using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

internal static class OsvEcosystemNames
{
    public static string? GetName(DependencyEcosystem ecosystem) => ecosystem switch
    {
        DependencyEcosystem.Npm => "npm",
        DependencyEcosystem.NuGet => "NuGet",
        DependencyEcosystem.Python => "PyPI",
        DependencyEcosystem.Maven => "Maven",
        DependencyEcosystem.Go => "Go",
        DependencyEcosystem.Cargo => "crates.io",
        DependencyEcosystem.Composer => "Packagist",
        DependencyEcosystem.Ruby => "RubyGems",
        DependencyEcosystem.Pub => "Pub",
        DependencyEcosystem.Hex => "Hex",
        DependencyEcosystem.Swift => "SwiftURL",
        _ => null
    };
}

internal static class OsvAdvisoryParser
{
    public static IReadOnlyList<VulnerabilityAdvisory> ParseQueryResponse(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("vulns", out var vulns) ||
            vulns.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return vulns
            .EnumerateArray()
            .Select(vulnerability => ParseAdvisory(vulnerability, null))
            .ToArray();
    }

    public static VulnerabilityAdvisory ParseAdvisory(
        string json,
        DependencyPackageInfo? package = null)
    {
        using var document = JsonDocument.Parse(json);
        return ParseAdvisory(document.RootElement, package);
    }

    public static VulnerabilityAdvisory CreateFallback(string id) =>
        new(
            id,
            [],
            "OSV matched this package version, but detailed advisory metadata was unavailable.",
            Severity.Medium,
            [],
            null,
            null);

    private static VulnerabilityAdvisory ParseAdvisory(
        JsonElement vulnerability,
        DependencyPackageInfo? package)
    {
        var id = ReadString(vulnerability, "id") ?? "UNKNOWN";
        var aliases = vulnerability.TryGetProperty("aliases", out var aliasesElement) &&
                      aliasesElement.ValueKind == JsonValueKind.Array
            ? aliasesElement
                .EnumerateArray()
                .Select(item => item.GetString())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!)
                .ToArray()
            : [];

        return new VulnerabilityAdvisory(
            id,
            aliases,
            ReadString(vulnerability, "summary") ?? id,
            ReadSeverity(vulnerability, package),
            ReadFixedVersions(vulnerability, package),
            ReadDate(vulnerability, "published"),
            ReadDate(vulnerability, "modified"));
    }

    private static Severity ReadSeverity(
        JsonElement vulnerability,
        DependencyPackageInfo? package)
    {
        if (vulnerability.TryGetProperty("database_specific", out var databaseSpecific) &&
            ReadString(databaseSpecific, "severity") is { } databaseSeverity &&
            TryParseSeverity(databaseSeverity, out var parsedDatabaseSeverity))
        {
            return parsedDatabaseSeverity;
        }

        if (vulnerability.TryGetProperty("affected", out var affected) &&
            affected.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in affected.EnumerateArray())
            {
                if (!MatchesAffectedPackage(item, package) ||
                    !item.TryGetProperty("ecosystem_specific", out var ecosystemSpecific) ||
                    ReadString(ecosystemSpecific, "severity") is not { } ecosystemSeverity ||
                    !TryParseSeverity(ecosystemSeverity, out var parsedEcosystemSeverity))
                {
                    continue;
                }

                return parsedEcosystemSeverity;
            }
        }

        if (vulnerability.TryGetProperty("severity", out var severityArray) &&
            severityArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var severity in severityArray.EnumerateArray())
            {
                if (double.TryParse(
                        ReadString(severity, "score"),
                        NumberStyles.Number,
                        CultureInfo.InvariantCulture,
                        out var numericScore))
                {
                    return SeverityFromScore(numericScore);
                }
            }
        }

        return Severity.Medium;
    }

    private static IReadOnlyList<string> ReadFixedVersions(
        JsonElement vulnerability,
        DependencyPackageInfo? package)
    {
        var versions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!vulnerability.TryGetProperty("affected", out var affected) ||
            affected.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        foreach (var item in affected.EnumerateArray())
        {
            if (!MatchesAffectedPackage(item, package) ||
                !item.TryGetProperty("ranges", out var ranges) ||
                ranges.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var range in ranges.EnumerateArray())
            {
                if (!range.TryGetProperty("events", out var events) ||
                    events.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var @event in events.EnumerateArray())
                {
                    if (ReadString(@event, "fixed") is { } fixedVersion)
                    {
                        versions.Add(fixedVersion);
                    }
                }
            }
        }

        return versions.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool MatchesAffectedPackage(
        JsonElement affected,
        DependencyPackageInfo? package)
    {
        if (package is null ||
            !affected.TryGetProperty("package", out var affectedPackage) ||
            affectedPackage.ValueKind != JsonValueKind.Object)
        {
            return true;
        }

        var affectedName = ReadString(affectedPackage, "name");
        var affectedEcosystem = ReadString(affectedPackage, "ecosystem");
        var expectedEcosystem = OsvEcosystemNames.GetName(package.Ecosystem);
        return (string.IsNullOrWhiteSpace(affectedName) ||
                affectedName.Equals(package.Name, StringComparison.OrdinalIgnoreCase)) &&
               (string.IsNullOrWhiteSpace(affectedEcosystem) ||
                affectedEcosystem.Equals(expectedEcosystem, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryParseSeverity(string value, out Severity severity)
    {
        severity = value.ToUpperInvariant() switch
        {
            "CRITICAL" => Severity.Critical,
            "HIGH" or "IMPORTANT" => Severity.High,
            "MODERATE" or "MEDIUM" => Severity.Medium,
            "LOW" => Severity.Low,
            _ => Severity.Info
        };

        return severity != Severity.Info;
    }

    private static Severity SeverityFromScore(double score) => score switch
    {
        >= 9 => Severity.Critical,
        >= 7 => Severity.High,
        >= 4 => Severity.Medium,
        _ => Severity.Low
    };

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : property.ToString();
    }

    private static DateTimeOffset? ReadDate(JsonElement element, string propertyName)
    {
        var value = ReadString(element, propertyName);
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;
    }
}

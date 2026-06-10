using System.Text.Json;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.PackageRegistries;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

public interface IOsvAdvisoryClient
{
    Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken);
}

public sealed class OsvAdvisoryClient(SafeHttpLookup lookup) : IOsvAdvisoryClient
{
    public async Task<IReadOnlyList<VulnerabilityAdvisory>> QueryAsync(
        DependencyPackageInfo package,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(package.Version))
        {
            return [];
        }

        var ecosystem = package.Ecosystem switch
        {
            DependencyEcosystem.Npm => "npm",
            DependencyEcosystem.NuGet => "NuGet",
            DependencyEcosystem.Python => "PyPI",
            _ => null
        };

        if (ecosystem is null)
        {
            return [];
        }

        var payload = JsonSerializer.Serialize(new
        {
            version = package.Version,
            package = new { name = package.Name, ecosystem }
        });
        var result = await lookup.PostJsonAsync(new Uri("https://api.osv.dev/v1/query"), payload, cancellationToken);
        return result.Success && result.Body is not null
            ? Parse(result.Body)
            : [];
    }

    public static IReadOnlyList<VulnerabilityAdvisory> Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var advisories = new List<VulnerabilityAdvisory>();
        foreach (var vuln in vulns.EnumerateArray())
        {
            var id = ReadString(vuln, "id") ?? "UNKNOWN";
            var aliases = vuln.TryGetProperty("aliases", out var aliasesElement) && aliasesElement.ValueKind == JsonValueKind.Array
                ? aliasesElement.EnumerateArray().Select(item => item.GetString()).Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!).ToArray()
                : [];
            var severity = ReadSeverity(vuln);
            var fixedVersions = ReadFixedVersions(vuln);
            advisories.Add(new VulnerabilityAdvisory(
                id,
                aliases,
                ReadString(vuln, "summary") ?? id,
                severity,
                fixedVersions,
                ReadDate(vuln, "published"),
                ReadDate(vuln, "modified")));
        }

        return advisories;
    }

    private static Severity ReadSeverity(JsonElement vuln)
    {
        if (vuln.TryGetProperty("database_specific", out var databaseSpecific) &&
            ReadString(databaseSpecific, "severity") is { } databaseSeverity)
        {
            return ParseSeverity(databaseSeverity);
        }

        if (vuln.TryGetProperty("severity", out var severityArray) && severityArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var severity in severityArray.EnumerateArray())
            {
                var score = ReadString(severity, "score");
                if (score is not null && score.Contains("CVSS:4.", StringComparison.OrdinalIgnoreCase))
                {
                    return Severity.Critical;
                }
            }
        }

        return Severity.High;
    }

    private static IReadOnlyList<string> ReadFixedVersions(JsonElement vuln)
    {
        var versions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!vuln.TryGetProperty("affected", out var affected) || affected.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        foreach (var item in affected.EnumerateArray())
        {
            if (!item.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var range in ranges.EnumerateArray())
            {
                if (!range.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
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

    private static Severity ParseSeverity(string value)
    {
        return value.ToUpperInvariant() switch
        {
            "CRITICAL" => Severity.Critical,
            "HIGH" => Severity.High,
            "MODERATE" or "MEDIUM" => Severity.Medium,
            "LOW" => Severity.Low,
            _ => Severity.High
        };
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
}

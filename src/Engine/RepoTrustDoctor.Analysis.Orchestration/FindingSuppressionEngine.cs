using RepoTrustDoctor.Domain;
using System.Text.Json;

namespace RepoTrustDoctor.Analysis.Orchestration;

public sealed class FindingSuppressionEngine
{
    public IReadOnlyList<string> Warnings { get; }

    private readonly Dictionary<string, List<FindingSuppression>> suppressionByRule;
    private readonly Dictionary<string, List<FindingSuppression>> suppressionByIdentity;

    private FindingSuppressionEngine(
        Dictionary<string, List<FindingSuppression>> byRule,
        Dictionary<string, List<FindingSuppression>> byIdentity,
        IReadOnlyList<string> warnings)
    {
        suppressionByRule = byRule;
        suppressionByIdentity = byIdentity;
        Warnings = warnings;
    }

    public static FindingSuppressionEngine Load(string repositoryRoot)
    {
        var configPath = Path.Combine(repositoryRoot, ".repo-trust.json");
        if (!File.Exists(configPath))
        {
            return new FindingSuppressionEngine(
                new Dictionary<string, List<FindingSuppression>>(StringComparer.OrdinalIgnoreCase),
                new Dictionary<string, List<FindingSuppression>>(StringComparer.OrdinalIgnoreCase),
                []);
        }

        return LoadFromFile(configPath);
    }

    public static FindingSuppressionEngine LoadFromFile(string configPath)
    {
        var warnings = new List<string>();
        var byRule = new Dictionary<string, List<FindingSuppression>>(StringComparer.OrdinalIgnoreCase);
        var byIdentity = new Dictionary<string, List<FindingSuppression>>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var content = File.ReadAllText(configPath);
            using var doc = System.Text.Json.JsonDocument.Parse(content);
            var root = doc.RootElement;

            if (root.TryGetProperty("suppressions", out var suppressions) &&
                suppressions.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var entry in suppressions.EnumerateArray())
                {
                    if (entry.ValueKind != System.Text.Json.JsonValueKind.Object)
                    {
                        warnings.Add("Invalid suppression entry in .repo-trust.json: expected an object.");
                        continue;
                    }

                    var ruleId = entry.TryGetProperty("ruleId", out var r) ? r.GetString() : null;
                    var reason = entry.TryGetProperty("reason", out var re) ? re.GetString() : null;
                    var path = entry.TryGetProperty("path", out var p) ? p.GetString() : null;
                    var identityKey = entry.TryGetProperty("identityKey", out var ik) ? ik.GetString() : null;
                    var owner = entry.TryGetProperty("owner", out var o) ? o.GetString() : null;
                    var expiresOnStr = entry.TryGetProperty("expiresOn", out var eo) ? eo.GetString() : null;

                    if (string.IsNullOrWhiteSpace(ruleId))
                    {
                        warnings.Add("Invalid suppression entry: 'ruleId' is required.");
                        continue;
                    }

                    if (string.IsNullOrWhiteSpace(reason))
                    {
                        warnings.Add($"Invalid suppression entry for rule '{ruleId}': 'reason' is required.");
                        continue;
                    }

                    DateOnly? expiresOn = null;
                    if (!string.IsNullOrWhiteSpace(expiresOnStr))
                    {
                        if (!DateOnly.TryParse(expiresOnStr, out var parsed))
                        {
                            warnings.Add($"Invalid suppression entry for rule '{ruleId}': 'expiresOn' has an invalid date format.");
                            continue;
                        }
                        expiresOn = parsed;
                    }

                    var suppression = new FindingSuppression(ruleId!, path, identityKey, reason!, owner, expiresOn);

                    if (!byRule.TryGetValue(ruleId!, out var ruleList))
                    {
                        ruleList = [];
                        byRule[ruleId!] = ruleList;
                    }
                    ruleList.Add(suppression);

                    if (!string.IsNullOrWhiteSpace(identityKey))
                    {
                        if (!byIdentity.TryGetValue(identityKey, out var identityList))
                        {
                            identityList = [];
                            byIdentity[identityKey] = identityList;
                        }
                        identityList.Add(suppression);
                    }
                }
            }
        }
        catch (System.Text.Json.JsonException)
        {
            warnings.Add("Invalid JSON in .repo-trust.json; suppressions were not loaded.");
        }
        catch (IOException)
        {
            warnings.Add("Could not read .repo-trust.json; suppressions were not loaded.");
        }

        return new FindingSuppressionEngine(byRule, byIdentity, warnings);
    }

    public FindingSuppression? FindActiveSuppression(Finding finding)
    {
        // Check identity key match (most specific)
        if (!string.IsNullOrWhiteSpace(finding.IdentityKey) &&
            suppressionByIdentity.TryGetValue(finding.IdentityKey, out var identitySuppressions))
        {
            foreach (var suppression in identitySuppressions)
            {
                if (IsSupressionActive(suppression) && MatchesPath(finding, suppression))
                {
                    return suppression;
                }
            }
        }

        // Check rule-only match
        if (suppressionByRule.TryGetValue(finding.RuleId, out var ruleSuppressions))
        {
            foreach (var suppression in ruleSuppressions)
            {
                if (IsSupressionActive(suppression) && MatchesPath(finding, suppression))
                {
                    return suppression;
                }
            }
        }

        return null;
    }

    private static bool IsSupressionActive(FindingSuppression suppression)
    {
        if (suppression.ExpiresOn is null)
        {
            return true;
        }

        return suppression.ExpiresOn.Value >= DateOnly.FromDateTime(DateTime.UtcNow);
    }

    private static bool MatchesPath(Finding finding, FindingSuppression suppression)
    {
        if (string.IsNullOrWhiteSpace(suppression.Path))
        {
            return true; // No path constraint
        }

        var evidencePath = finding.Evidence
            .Select(e => e.FilePath)
            .FirstOrDefault(p => !string.IsNullOrWhiteSpace(p));

        if (evidencePath is null)
        {
            return false;
        }

        // Simple exact or suffix match
        return evidencePath.Equals(suppression.Path, StringComparison.OrdinalIgnoreCase) ||
               evidencePath.EndsWith("/" + suppression.Path, StringComparison.OrdinalIgnoreCase) ||
               evidencePath.Replace('\\', '/').EndsWith("/" + suppression.Path.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase);
    }
}

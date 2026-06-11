using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Reporting;

public sealed class JsonReportWriter
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public string Write(RepositoryScan scan)
    {
        var sorted = scan with { Findings = SortFindings(FindingFingerprinter.AddFingerprints(scan.Findings)) };
        return JsonSerializer.Serialize(sorted, Options);
    }

    public static IReadOnlyList<Finding> SortFindings(IReadOnlyList<Finding> findings)
    {
        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Evidence.FirstOrDefault()?.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Evidence.FirstOrDefault()?.LineNumber)
            .ToArray();
    }
}

public sealed class MarkdownReportWriter
{
    public string Write(RepositoryScan scan)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"# Repository Trust Report");
        builder.AppendLine();
        builder.AppendLine($"- Target: `{scan.Target}`");
        builder.AppendLine($"- Tool version: `{scan.ToolVersion}`");
        builder.AppendLine($"- Scan mode: `{scan.Depth}`");
        builder.AppendLine($"- Trust profile: `{scan.TrustProfile}`");
        builder.AppendLine($"- Overall score: `{scan.Score.Overall}/100`");
        builder.AppendLine($"- Decision: `{scan.Score.Decision.Kind}`");
        builder.AppendLine();

        var summary = scan.Summary;
        builder.AppendLine("## Finding Summary");
        builder.AppendLine();
        builder.AppendLine($"| Severity | Count |");
        builder.AppendLine($"| -------- | ----- |");
        builder.AppendLine($"| Critical | {summary.Critical} |");
        builder.AppendLine($"| High     | {summary.High} |");
        builder.AppendLine($"| Medium   | {summary.Medium} |");
        builder.AppendLine($"| Low      | {summary.Low} |");
        builder.AppendLine($"| Info     | {summary.Info} |");
        builder.AppendLine($"| **Total**    | **{summary.Total}** |");
        builder.AppendLine($"| Blocking | {summary.Blocking} |");
        builder.AppendLine();

        builder.AppendLine("## Decision Reasons");
        foreach (var reason in scan.Score.Decision.Reasons)
        {
            builder.AppendLine($"- {reason}");
        }

        builder.AppendLine();
        builder.AppendLine("## Modules");
        foreach (var module in scan.Modules)
        {
            builder.AppendLine($"- `{module.ModuleId}`: {module.Status} ({module.FindingsCount} findings)");
        }

        builder.AppendLine();
        AppendDependencySummary(builder, scan);
        AppendRecommendedActions(builder, scan);

        builder.AppendLine();
        builder.AppendLine("## Findings");
        var findings = JsonReportWriter.SortFindings(FindingFingerprinter.AddFingerprints(scan.Findings));
        if (findings.Count == 0)
        {
            builder.AppendLine("No findings were produced by the completed modules.");
        }
        else
        {
            foreach (var finding in findings)
            {
                builder.AppendLine($"### {finding.RuleId} - {finding.Title}");
                builder.AppendLine();
                builder.AppendLine($"- Severity: `{finding.Severity}`");
                builder.AppendLine($"- Confidence: `{finding.Confidence}`");
                builder.AppendLine($"- Category: `{finding.Category}`");
                builder.AppendLine($"- Fingerprint: `{finding.Fingerprint}`");
                builder.AppendLine($"- Message: {finding.Message}");
                builder.AppendLine($"- Recommendation: {finding.Recommendation.Message}");
                foreach (var evidence in finding.Evidence)
                {
                    var location = evidence.FilePath is null ? string.Empty : $" `{evidence.FilePath}`";
                    builder.AppendLine($"- Evidence: {evidence.Message}{location}");
                }

                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static void AppendDependencySummary(StringBuilder builder, RepositoryScan scan)
    {
        if (scan.Artifacts is null ||
            !scan.Artifacts.TryGetValue(DependencyInventoryArtifact.ArtifactKey, out var rawArtifact) ||
            rawArtifact is not DependencyInventoryArtifact inventory)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine("## Dependency Inventory");
        builder.AppendLine();
        builder.AppendLine($"- Manifests: `{inventory.Manifests.Count}`");
        builder.AppendLine($"- Lockfiles: `{inventory.Lockfiles.Count}`");
        builder.AppendLine($"- Packages: `{inventory.Packages.Count}`");
        builder.AppendLine($"- Package sources: `{inventory.PackageSources.Count}`");
        builder.AppendLine($"- Unpinned or ranged packages: `{inventory.Packages.Count(package => !package.IsVersionPinned)}`");
        builder.AppendLine($"- Prerelease packages: `{inventory.Packages.Count(package => package.IsPrerelease)}`");
        builder.AppendLine($"- Direct remote npm sources: `{inventory.Packages.Count(package => package.Ecosystem == DependencyEcosystem.Npm && package.Metadata?.TryGetValue("sourceKind", out var kind) == true && kind.Equals("remote", StringComparison.OrdinalIgnoreCase))}`");
        builder.AppendLine($"- Local npm sources: `{inventory.Packages.Count(package => package.Ecosystem == DependencyEcosystem.Npm && package.Metadata?.TryGetValue("sourceKind", out var kind) == true && kind.Equals("local", StringComparison.OrdinalIgnoreCase))}`");
        builder.AppendLine($"- Insecure package sources: `{inventory.PackageSources.Count(source => !source.IsSecureTransport)}`");
        builder.AppendLine($"- Local package sources: `{inventory.PackageSources.Count(source => source.IsLocal)}`");
        builder.AppendLine();

        builder.AppendLine("| Ecosystem | Manifests | Lockfiles | Packages |");
        builder.AppendLine("| --------- | --------- | --------- | -------- |");
        foreach (var ecosystem in Enum.GetValues<DependencyEcosystem>())
        {
            var manifestCount = inventory.Manifests.Count(manifest => manifest.Ecosystem == ecosystem);
            var lockfileCount = inventory.Lockfiles.Count(lockfile => lockfile.Ecosystem == ecosystem);
            var packageCount = inventory.Packages.Count(package => package.Ecosystem == ecosystem);
            if (manifestCount == 0 && lockfileCount == 0 && packageCount == 0)
            {
                continue;
            }

            builder.AppendLine($"| {ecosystem} | {manifestCount} | {lockfileCount} | {packageCount} |");
        }
    }

    private static void AppendRecommendedActions(StringBuilder builder, RepositoryScan scan)
    {
        var findings = JsonReportWriter.SortFindings(scan.Findings);
        if (findings.Count == 0)
        {
            return;
        }

        var actions = findings
            .Select(finding => finding.Recommendation.Message)
            .Where(message => !string.IsNullOrWhiteSpace(message))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();

        if (actions.Length == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.AppendLine("## Top Recommended Actions");
        foreach (var action in actions)
        {
            builder.AppendLine($"- {action}");
        }
    }
}

public sealed class SarifReportWriter
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string Write(RepositoryScan scan)
    {
        var findings = JsonReportWriter.SortFindings(FindingFingerprinter.AddFingerprints(scan.Findings));
        var rules = findings
            .GroupBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var finding = group.First();
                return new SarifRule(
                    finding.RuleId,
                    new SarifText(finding.Title),
                    new SarifText(finding.Recommendation.Message),
                    new Dictionary<string, object?>
                    {
                        ["category"] = finding.Category.ToString(),
                        ["defaultSeverity"] = finding.Severity.ToString()
                    },
                    BuildHelpUri(finding.RuleId));
            })
            .ToArray();

        var results = findings.Select(finding =>
        {
            var evidence = finding.Evidence.FirstOrDefault(evidence => !string.IsNullOrWhiteSpace(evidence.FilePath));
            var locations = evidence is null
                ? null
                : new[]
                {
                    new SarifLocation(new SarifPhysicalLocation(
                        new SarifArtifactLocation(evidence.FilePath!.Replace('\\', '/')),
                        evidence.LineNumber is null ? null : new SarifRegion(evidence.LineNumber.Value)))
                };

            return new SarifResult(
                finding.RuleId,
                MapLevel(finding.Severity),
                new SarifText($"{finding.Title}. {finding.Message}"),
                locations,
                new Dictionary<string, string>
                {
                    ["repoTrustDoctorFingerprint"] = finding.Fingerprint ?? FindingFingerprinter.Compute(finding)
                },
                new Dictionary<string, object?>
                {
                    ["confidence"] = finding.Confidence.ToString(),
                    ["category"] = finding.Category.ToString(),
                    ["evidenceKind"] = finding.Evidence.FirstOrDefault()?.Kind,
                    ["isBlocking"] = finding.IsBlocking,
                    ["tags"] = finding.Tags
                });
        }).ToArray();

        var sarif = new SarifLog(
            "2.1.0",
            "https://json.schemastore.org/sarif-2.1.0.json",
            [
                new SarifRun(
                    new SarifTool(new SarifDriver("Repository Trust Doctor", scan.ToolVersion, rules)),
                    results)
            ]);

        return JsonSerializer.Serialize(sarif, Options);
    }

    private static Uri? BuildHelpUri(string ruleId)
    {
        var categoryFile = GetCategoryDocFile(ruleId);
        if (categoryFile is null) return null;
        var anchor = $"#{ruleId.ToLowerInvariant().Replace("trust-", "trust-")}";
        return new Uri($"https://github.com/Wezylnia/repo-trust-doctor/blob/main/docs/rules/{categoryFile}.md{anchor}");
    }

    private static string? GetCategoryDocFile(string ruleId)
    {
        if (ruleId.StartsWith("TRUST-SECRET", StringComparison.OrdinalIgnoreCase)) return "secrets";
        if (ruleId.StartsWith("TRUST-GHA", StringComparison.OrdinalIgnoreCase)) return "github-actions";
        if (ruleId.StartsWith("TRUST-DOCKER", StringComparison.OrdinalIgnoreCase)) return "docker";
        if (ruleId.StartsWith("TRUST-DEP", StringComparison.OrdinalIgnoreCase)) return "dependencies";
        if (ruleId.StartsWith("TRUST-REPO", StringComparison.OrdinalIgnoreCase)) return "repository";
        if (ruleId.StartsWith("TRUST-CODE", StringComparison.OrdinalIgnoreCase)) return "codebase";
        if (ruleId.StartsWith("TRUST-REL", StringComparison.OrdinalIgnoreCase)) return "releases";
        if (ruleId.StartsWith("TRUST-VULN", StringComparison.OrdinalIgnoreCase)) return "vulnerabilities";
        if (ruleId.StartsWith("TRUST-LIC", StringComparison.OrdinalIgnoreCase)) return "licenses";
        if (ruleId.StartsWith("TRUST-ORIGIN", StringComparison.OrdinalIgnoreCase)) return "dependencies";
        if (ruleId.StartsWith("TRUST-WS", StringComparison.OrdinalIgnoreCase)) return "repository";
        if (ruleId.StartsWith("TRUST-GLCI", StringComparison.OrdinalIgnoreCase)) return "gitlab-ci";
        if (ruleId.StartsWith("TRUST-COMP", StringComparison.OrdinalIgnoreCase)) return "docker";
        if (ruleId.StartsWith("TRUST-K8S", StringComparison.OrdinalIgnoreCase)) return "kubernetes";
        if (ruleId.StartsWith("TRUST-EVI", StringComparison.OrdinalIgnoreCase)) return "releases";
        if (ruleId.StartsWith("TRUST-AZP", StringComparison.OrdinalIgnoreCase)) return "azure-pipelines";
        if (ruleId.StartsWith("TRUST-CIRCLE", StringComparison.OrdinalIgnoreCase)) return "circleci";
        if (ruleId.StartsWith("TRUST-TF", StringComparison.OrdinalIgnoreCase)) return "terraform";
        if (ruleId.StartsWith("TRUST-REG", StringComparison.OrdinalIgnoreCase)) return "dependencies";
        return null;
    }

    private static string MapLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium or Severity.Low => "warning",
        Severity.Info => "note",
        _ => "none"
    };

    private sealed record SarifLog(
        string Version,
        [property: JsonPropertyName("$schema")] string Schema,
        IReadOnlyList<SarifRun> Runs);
    private sealed record SarifRun(SarifTool Tool, IReadOnlyList<SarifResult> Results);
    private sealed record SarifTool(SarifDriver Driver);
    private sealed record SarifDriver(string Name, string SemanticVersion, IReadOnlyList<SarifRule> Rules);
    private sealed record SarifRule(string Id, SarifText ShortDescription, SarifText Help, IReadOnlyDictionary<string, object?> Properties, Uri? HelpUri = null);
    private sealed record SarifResult(
        string RuleId,
        string Level,
        SarifText Message,
        IReadOnlyList<SarifLocation>? Locations,
        IReadOnlyDictionary<string, string> PartialFingerprints,
        IReadOnlyDictionary<string, object?> Properties);
    private sealed record SarifText(string Text);
    private sealed record SarifLocation(SarifPhysicalLocation PhysicalLocation);
    private sealed record SarifPhysicalLocation(SarifArtifactLocation ArtifactLocation, SarifRegion? Region);
    private sealed record SarifArtifactLocation(string Uri);
    private sealed record SarifRegion(int StartLine);
}

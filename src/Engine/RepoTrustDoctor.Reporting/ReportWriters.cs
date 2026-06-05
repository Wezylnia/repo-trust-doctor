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

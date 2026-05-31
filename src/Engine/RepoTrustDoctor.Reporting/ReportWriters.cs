using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
        var sorted = scan with { Findings = SortFindings(scan.Findings) };
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
        builder.AppendLine("## Findings");
        if (scan.Findings.Count == 0)
        {
            builder.AppendLine("No findings were produced by the completed modules.");
        }
        else
        {
            foreach (var finding in JsonReportWriter.SortFindings(scan.Findings))
            {
                builder.AppendLine($"### {finding.RuleId} - {finding.Title}");
                builder.AppendLine();
                builder.AppendLine($"- Severity: `{finding.Severity}`");
                builder.AppendLine($"- Confidence: `{finding.Confidence}`");
                builder.AppendLine($"- Category: `{finding.Category}`");
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
}

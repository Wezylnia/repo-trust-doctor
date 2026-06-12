using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Shared;
using RepoTrustDoctor.TrustHistory;

internal sealed record DiffCommandOptions(
    string BeforeReportPath,
    string AfterReportPath,
    string Format,
    string? OutputPath,
    bool ForceOutput);

internal static partial class CliProgram
{
    private static readonly string[] SupportedDiffFormats = ["console", "json", "markdown", "md"];

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static async Task<int> RunDiffAsync(string[] args, CancellationToken cancellationToken)
    {
        if (!TryParseDiffOptions(args, out var options, out var error))
        {
            Console.Error.WriteLine(error);
            PrintHelp();
            return 1;
        }

        RepositoryScan before;
        RepositoryScan after;
        try
        {
            before = await ReadScanReportAsync(options.BeforeReportPath, cancellationToken);
            after = await ReadScanReportAsync(options.AfterReportPath, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            Console.Error.WriteLine($"Could not read scan report: {ex.Message}");
            return 2;
        }

        var snapshotFactory = new TrustSnapshotFactory();
        var diff = new TrustDiffEngine().Compare(snapshotFactory.Create(before), snapshotFactory.Create(after));
        var output = options.Format.ToLowerInvariant() switch
        {
            "json" => JsonSerializer.Serialize(diff, JsonOptions),
            "markdown" or "md" => BuildDiffMarkdown(diff),
            "console" => BuildDiffConsoleSummary(diff),
            _ => throw new ArgumentException($"Unsupported format: {options.Format}")
        };

        return await WriteOutputAsync(output, options.OutputPath, options.ForceOutput, cancellationToken);
    }

    internal static bool TryParseDiffOptions(string[] args, out DiffCommandOptions options, out string error)
    {
        options = default!;
        error = string.Empty;

        var positional = new List<string>();
        var format = "console";
        string? outputPath = null;
        var forceOutput = false;

        for (var index = 1; index < args.Length; index++)
        {
            var arg = args[index];
            switch (arg)
            {
                case "--format":
                    if (!TryReadOptionValue(args, ref index, arg, out format, out error))
                    {
                        return false;
                    }
                    break;
                case "--output":
                    if (!TryReadOptionValue(args, ref index, arg, out var parsedOutputPath, out error))
                    {
                        return false;
                    }
                    outputPath = parsedOutputPath;
                    break;
                case "--force":
                    forceOutput = true;
                    break;
                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal) && arg.Length > 1)
                    {
                        error = $"Unknown option: {arg}";
                        return false;
                    }

                    positional.Add(arg);
                    break;
            }
        }

        if (positional.Count != 2)
        {
            error = "diff requires exactly two JSON scan report paths.";
            return false;
        }

        if (!SupportedDiffFormats.Contains(format, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Unsupported diff format: {format}. Supported formats: {string.Join(", ", SupportedDiffFormats)}";
            return false;
        }

        options = new DiffCommandOptions(positional[0], positional[1], format, outputPath, forceOutput);
        return true;
    }

    private static async Task<RepositoryScan> ReadScanReportAsync(string reportPath, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(reportPath);
        return await JsonSerializer.DeserializeAsync<RepositoryScan>(stream, JsonOptions, cancellationToken)
            ?? throw new JsonException("Scan report is empty or invalid.");
    }

    private static string BuildDiffConsoleSummary(TrustDiffResult diff)
    {
        var lines = new List<string>
        {
            ProductInfo.Name,
            "Trust diff",
            $"Before: {diff.Before.Target} ({diff.Before.OverallScore}/100, {diff.Before.Decision})",
            $"After: {diff.After.Target} ({diff.After.OverallScore}/100, {diff.After.Decision})",
            $"Score delta: {FormatDelta(diff.OverallScoreDelta)}",
            $"Decision changed: {diff.DecisionChanged}",
            $"New findings: {diff.NewFindings.Count}",
            $"Resolved findings: {diff.ResolvedFindings.Count}",
            $"Worsened findings: {diff.WorsenedFindings.Count}",
            $"Improved findings: {diff.ImprovedFindings.Count}",
            string.Empty,
            "Top new findings:"
        };

        lines.AddRange(diff.NewFindings
            .Take(10)
            .Select(finding => $"- [{finding.Severity}] {finding.RuleId}: {finding.Title}"));

        if (diff.NewFindings.Count == 0)
        {
            lines.Add("- none");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildDiffMarkdown(TrustDiffResult diff)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Repository Trust Diff");
        builder.AppendLine();
        builder.AppendLine($"- Before: `{diff.Before.Target}` (`{diff.Before.OverallScore}/100`, `{diff.Before.Decision}`)");
        builder.AppendLine($"- After: `{diff.After.Target}` (`{diff.After.OverallScore}/100`, `{diff.After.Decision}`)");
        builder.AppendLine($"- Score delta: `{FormatDelta(diff.OverallScoreDelta)}`");
        builder.AppendLine($"- Decision changed: `{diff.DecisionChanged}`");
        builder.AppendLine();
        builder.AppendLine("## Finding Changes");
        builder.AppendLine();
        builder.AppendLine($"- New: `{diff.NewFindings.Count}`");
        builder.AppendLine($"- Resolved: `{diff.ResolvedFindings.Count}`");
        builder.AppendLine($"- Worsened: `{diff.WorsenedFindings.Count}`");
        builder.AppendLine($"- Improved: `{diff.ImprovedFindings.Count}`");
        builder.AppendLine($"- Unchanged: `{diff.UnchangedFindings.Count}`");
        AppendFindings(builder, "New Findings", diff.NewFindings);
        AppendFindings(builder, "Resolved Findings", diff.ResolvedFindings);
        return builder.ToString();
    }

    private static void AppendFindings(StringBuilder builder, string title, IReadOnlyList<FindingSnapshot> findings)
    {
        builder.AppendLine();
        builder.AppendLine($"## {title}");
        if (findings.Count == 0)
        {
            builder.AppendLine();
            builder.AppendLine("None.");
            return;
        }

        foreach (var finding in findings.Take(20))
        {
            var location = string.IsNullOrWhiteSpace(finding.FilePath) ? string.Empty : $" `{finding.FilePath}`";
            builder.AppendLine($"- `{finding.Severity}` `{finding.RuleId}` {finding.Title}{location}");
        }
    }

    private static string FormatDelta(int delta) => delta > 0 ? $"+{delta}" : delta.ToString();
}

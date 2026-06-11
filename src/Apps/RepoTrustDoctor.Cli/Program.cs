using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Reporting;
using RepoTrustDoctor.Shared;
using RepoTrustDoctor.TrustHistory;

var exitCode = await CliProgram.RunAsync(args, CancellationToken.None);
return exitCode;

internal sealed record ScanCommandOptions(
    string Target,
    string Format,
    string? OutputPath,
    bool ForceOutput,
    AnalysisDepth Depth,
    TrustProfile TrustProfile,
    int? FailUnderScore,
    Severity? FailOnSeverity);

internal sealed record DiffCommandOptions(
    string BeforeReportPath,
    string AfterReportPath,
    string Format,
    string? OutputPath,
    bool ForceOutput);

internal static class CliProgram
{
    private static readonly string[] SupportedFormats = ["console", "json", "markdown", "md", "sarif"];
    private static readonly string[] SupportedDiffFormats = ["console", "json", "markdown", "md"];
    private static readonly string[] SupportedDepths = ["fast", "standard", "deep"];
    private static readonly string[] SupportedProfileNames = ["Personal", "ProductionDependency", "SecuritySensitiveDependency"];
    private static readonly Dictionary<string, TrustProfile> SupportedProfileAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["personal"] = TrustProfile.Personal,
        ["production"] = TrustProfile.ProductionDependency,
        ["prod"] = TrustProfile.ProductionDependency,
        ["enterprise"] = TrustProfile.SecuritySensitiveDependency,
        ["enterprise-dependency"] = TrustProfile.SecuritySensitiveDependency,
        ["cicd"] = TrustProfile.ProductionDependency,
        ["ci-cd"] = TrustProfile.ProductionDependency,
        ["ci"] = TrustProfile.ProductionDependency,
        ["security"] = TrustProfile.SecuritySensitiveDependency,
        ["security-sensitive"] = TrustProfile.SecuritySensitiveDependency,
        ["container"] = TrustProfile.ProductionDependency,
        ["docker"] = TrustProfile.ProductionDependency
    };

    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length > 0 && args[0] is "--version" or "-v" or "version")
        {
            Console.WriteLine($"{ProductInfo.CommandName} {ProductInfo.Version}");
            return 0;
        }

        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintHelp();
            return args.Length == 0 ? 1 : 0;
        }

        if (string.Equals(args[0], "diff", StringComparison.OrdinalIgnoreCase))
        {
            return await RunDiffAsync(args, cancellationToken);
        }

        if (!string.Equals(args[0], "scan", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"Unknown command: {args[0]}");
            PrintHelp();
            return 1;
        }

        if (!TryParseScanOptions(args, out var options, out var error))
        {
            Console.Error.WriteLine(error);
            PrintHelp();
            return 1;
        }

        var scan = await new DefaultRepositoryScanRunner().RunAsync(
            new ScanRequestOptions(options.Target, options.Depth, options.TrustProfile),
            cancellationToken);

        var output = options.Format.ToLowerInvariant() switch
        {
            "json" => new JsonReportWriter().Write(scan),
            "markdown" or "md" => new MarkdownReportWriter().Write(scan),
            "sarif" => new SarifReportWriter().Write(scan),
            "console" => BuildConsoleSummary(scan),
            _ => throw new ArgumentException($"Unsupported format: {options.Format}")
        };

        var outputExitCode = await WriteOutputAsync(output, options.OutputPath, options.ForceOutput, cancellationToken);
        if (outputExitCode != 0)
        {
            return outputExitCode;
        }

        return ComputeExitCode(scan, options);
    }

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

    internal static bool TryParseScanOptions(string[] args, out ScanCommandOptions options, out string error)
    {
        options = default!;
        error = string.Empty;

        var target = ".";
        var hasTarget = false;
        var format = "console";
        string? outputPath = null;
        var forceOutput = false;
        var depthValue = "fast";
        var profileValue = nameof(TrustProfile.ProductionDependency);
        int? failUnderScore = null;
        Severity? failOnSeverity = null;

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
                case "--depth":
                    if (!TryReadOptionValue(args, ref index, arg, out depthValue, out error))
                    {
                        return false;
                    }
                    break;
                case "--profile":
                    if (!TryReadOptionValue(args, ref index, arg, out profileValue, out error))
                    {
                        return false;
                    }
                    break;
                case "--fail-under":
                    if (!TryReadOptionValue(args, ref index, arg, out var failUnderValue, out error))
                    {
                        return false;
                    }

                    if (!int.TryParse(failUnderValue, out var parsedFailUnder) || parsedFailUnder is < 0 or > 100)
                    {
                        error = "--fail-under must be an integer between 0 and 100.";
                        return false;
                    }

                    failUnderScore = parsedFailUnder;
                    break;
                case "--fail-on-severity":
                    if (!TryReadOptionValue(args, ref index, arg, out var failOnSeverityValue, out error))
                    {
                        return false;
                    }

                    if (!Enum.TryParse<Severity>(failOnSeverityValue, ignoreCase: true, out var parsedFailOnSeverity))
                    {
                        error = $"Unsupported severity: {failOnSeverityValue}. Supported severities: {string.Join(", ", Enum.GetNames<Severity>())}";
                        return false;
                    }

                    failOnSeverity = parsedFailOnSeverity;
                    break;
                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal) && arg.Length > 1)
                    {
                        error = $"Unknown option: {arg}";
                        return false;
                    }

                    if (hasTarget)
                    {
                        error = $"Unexpected argument: {arg}";
                        return false;
                    }

                    target = arg;
                    hasTarget = true;
                    break;
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Unsupported format: {format}. Supported formats: {string.Join(", ", SupportedFormats)}";
            return false;
        }

        if (!SupportedDepths.Contains(depthValue, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Unsupported depth: {depthValue}. Supported depths: {string.Join(", ", SupportedDepths)}";
            return false;
        }

        if (!TryParseTrustProfile(profileValue, out var normalizedProfile))
        {
            error = $"Unsupported profile: {profileValue}. Supported profiles: {string.Join(", ", SupportedProfileNames)}";
            return false;
        }

        var depth = depthValue.ToLowerInvariant() switch
        {
            "fast" => AnalysisDepth.Fast,
            "standard" => AnalysisDepth.Standard,
            "deep" => AnalysisDepth.Deep,
            _ => AnalysisDepth.Fast
        };

        options = new ScanCommandOptions(target, format, outputPath, forceOutput, depth, normalizedProfile, failUnderScore, failOnSeverity);
        return true;
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

    private static bool TryParseTrustProfile(string profileValue, out TrustProfile profile)
    {
        if (Enum.TryParse(profileValue, ignoreCase: true, out profile))
        {
            profile = TrustProfileCatalog.Normalize(profile);
            return true;
        }

        return SupportedProfileAliases.TryGetValue(profileValue, out profile);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static async Task<RepositoryScan> ReadScanReportAsync(string reportPath, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(reportPath);
        return await JsonSerializer.DeserializeAsync<RepositoryScan>(stream, JsonOptions, cancellationToken)
            ?? throw new JsonException("Scan report is empty or invalid.");
    }

    private static bool TryReadOptionValue(string[] args, ref int index, string name, out string value, out string error)
    {
        value = string.Empty;
        error = string.Empty;

        if (index + 1 >= args.Length || args[index + 1].StartsWith("-", StringComparison.Ordinal))
        {
            error = $"Missing value for option: {name}";
            return false;
        }

        value = args[++index];
        return true;
    }

    private static async Task<int> WriteOutputAsync(string output, string? outputPath, bool forceOutput, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine(output);
            return 0;
        }

        var fullOutputPath = Path.GetFullPath(outputPath);
        var outputDirectory = Path.GetDirectoryName(fullOutputPath);
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        if (File.Exists(fullOutputPath) && !forceOutput)
        {
            Console.Error.WriteLine($"Refusing to overwrite existing report: {fullOutputPath}");
            Console.Error.WriteLine("Use --force to overwrite it.");
            return 2;
        }

        await File.WriteAllTextAsync(fullOutputPath, output, cancellationToken);
        Console.WriteLine($"Report written to {fullOutputPath}");
        return 0;
    }

    private static string BuildConsoleSummary(RepositoryScan scan)
    {
        var summary = scan.Summary;
        var lines = new List<string>
        {
            ProductInfo.Name,
            $"Version: {scan.ToolVersion}",
            $"Target: {scan.Target}",
            $"Depth: {scan.Depth}",
            $"Trust profile: {scan.TrustProfile}",
            $"Score: {scan.Score.Overall}/100",
            $"Decision: {scan.Score.Decision.Kind}",
            $"Findings: {scan.Findings.Count}",
            $"Severity summary: Critical={summary.Critical}, High={summary.High}, Medium={summary.Medium}, Low={summary.Low}, Info={summary.Info}",
            string.Empty,
            "Top findings:"
        };

        lines.AddRange(scan.Findings
            .OrderByDescending(finding => finding.Severity)
            .Take(10)
            .Select(finding => $"- [{finding.Severity}] {finding.RuleId}: {finding.Title}"));

        if (scan.Findings.Count == 0)
        {
            lines.Add("- none");
        }

        return string.Join(Environment.NewLine, lines);
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

    internal static int ComputeExitCode(RepositoryScan scan, ScanCommandOptions options)
    {
        if (options.FailUnderScore is int minimumScore && scan.Score.Overall < minimumScore)
        {
            return 4;
        }

        if (options.FailOnSeverity is Severity minimumSeverity &&
            scan.Findings.Any(finding => finding.Severity >= minimumSeverity))
        {
            return 4;
        }

        return scan.Score.Decision.Kind == FinalDecisionKind.AvoidAsProductionDependency ? 3 : 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
        Repository Trust Doctor

        Version:
          repo-trust-doctor --version

        Usage:
          repo-trust-doctor scan <path-or-url> [options]
          repo-trust-doctor diff <before.json> <after.json> [options]

        Options:
          --format console|json|markdown|md|sarif
                                              Report format (default: console)
          --output <file>                     Write report to file instead of stdout
          --force                             Overwrite existing report file
          --depth fast|standard|deep          Scan depth (default: fast)
          --profile <name>                    Trust profile (default: ProductionDependency)
          --fail-under <0-100>                Exit 4 if the score is below this value
          --fail-on-severity <severity>       Exit 4 if any finding is at or above this severity

        Diff options:
          --format console|json|markdown|md   Diff report format (default: console)
          --output <file>                     Write diff report to file instead of stdout
          --force                             Overwrite existing diff report file

        Supported profiles:
          Personal, ProductionDependency, SecuritySensitiveDependency
          Common aliases: production, enterprise, security
          Legacy ci-cd/container aliases are accepted and mapped to production.

        Exit codes:
          0   Scan completed, no blocking decision
          1   CLI usage error
          2   Input/output error
          3   Scan completed with AvoidAsProductionDependency decision
          4   Configured CI gate failed
        """);
    }
}

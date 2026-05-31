using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analysis.Engine;
using RepoTrustDoctor.Analysis.Orchestration;
using RepoTrustDoctor.Analyzers.Docker;
using RepoTrustDoctor.Analyzers.GitHubActions;
using RepoTrustDoctor.Analyzers.Repository;
using RepoTrustDoctor.Analyzers.Secrets;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Git;
using RepoTrustDoctor.Reporting;
using RepoTrustDoctor.Scoring;

var exitCode = await CliProgram.RunAsync(args, CancellationToken.None);
return exitCode;

internal sealed record ScanCommandOptions(
    string Target,
    string Format,
    string? OutputPath,
    bool ForceOutput,
    AnalysisDepth Depth,
    string TrustProfile);

internal static class CliProgram
{
    private static readonly string[] SupportedFormats = ["console", "json", "markdown", "md"];
    private static readonly string[] SupportedDepths = ["fast", "standard", "deep"];
    private static readonly Dictionary<string, string> SupportedProfiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["personal"] = "Personal",
        ["production"] = "ProductionDependency",
        ["prod"] = "ProductionDependency",
        ["productiondependency"] = "ProductionDependency",
        ["enterprise"] = "EnterpriseDependency",
        ["enterprisedependency"] = "EnterpriseDependency",
        ["cicd"] = "CiCdTool",
        ["ci-cd"] = "CiCdTool",
        ["cicdtool"] = "CiCdTool",
        ["security"] = "SecuritySensitiveDependency",
        ["security-sensitive"] = "SecuritySensitiveDependency",
        ["securitysensitivedependency"] = "SecuritySensitiveDependency",
        ["container"] = "ContainerDependency",
        ["containerdependency"] = "ContainerDependency"
    };

    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintHelp();
            return args.Length == 0 ? 1 : 0;
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

        IRepositoryAnalyzer[] analyzers =
        [
            new RepositoryHealthAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer()
        ];

        using var workspace = await PrepareWorkspaceAsync(options.Target, cancellationToken);
        var orchestrator = new ScanOrchestrator(analyzers, new AnalyzerExecutor(), new TrustScorer());
        var scan = await orchestrator.RunAsync(options.Target, workspace.Path, options.Depth, options.TrustProfile, cancellationToken);

        var output = options.Format.ToLowerInvariant() switch
        {
            "json" => new JsonReportWriter().Write(scan),
            "markdown" or "md" => new MarkdownReportWriter().Write(scan),
            "console" => BuildConsoleSummary(scan),
            _ => throw new ArgumentException($"Unsupported format: {options.Format}")
        };

        if (string.IsNullOrWhiteSpace(options.OutputPath))
        {
            Console.WriteLine(output);
        }
        else
        {
            var fullOutputPath = Path.GetFullPath(options.OutputPath);
            var outputDirectory = Path.GetDirectoryName(fullOutputPath);
            if (!string.IsNullOrEmpty(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            if (File.Exists(fullOutputPath) && !options.ForceOutput)
            {
                Console.Error.WriteLine($"Refusing to overwrite existing report: {fullOutputPath}");
                Console.Error.WriteLine("Use --force to overwrite it.");
                return 2;
            }

            await File.WriteAllTextAsync(fullOutputPath, output, cancellationToken);
            Console.WriteLine($"Report written to {fullOutputPath}");
        }

        return scan.Score.Decision.Kind == FinalDecisionKind.AvoidAsProductionDependency ? 3 : 0;
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
        var profileValue = "ProductionDependency";

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

        if (!SupportedProfiles.TryGetValue(profileValue, out var normalizedProfile))
        {
            error = $"Unsupported profile: {profileValue}. Supported profiles: {string.Join(", ", SupportedProfiles.Keys)}";
            return false;
        }

        var depth = depthValue.ToLowerInvariant() switch
        {
            "fast" => AnalysisDepth.Fast,
            "standard" => AnalysisDepth.Standard,
            "deep" => AnalysisDepth.Deep,
            _ => AnalysisDepth.Fast
        };

        options = new ScanCommandOptions(target, format, outputPath, forceOutput, depth, normalizedProfile);
        return true;
    }

    private static Task<RepositoryWorkspace> PrepareWorkspaceAsync(string target, CancellationToken cancellationToken)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return RepositoryWorkspace.CloneFromUrlAsync(target, cancellationToken);
        }

        return Task.FromResult(RepositoryWorkspace.ForLocalPath(target));
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

    private static string BuildConsoleSummary(RepositoryScan scan)
    {
        var lines = new List<string>
        {
            "Repository Trust Doctor",
            $"Target: {scan.Target}",
            $"Score: {scan.Score.Overall}/100",
            $"Decision: {scan.Score.Decision.Kind}",
            $"Findings: {scan.Findings.Count}",
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

    private static void PrintHelp()
    {
        Console.WriteLine("""
        Repository Trust Doctor

        Usage:
          repo-trust-doctor scan <path-or-url> [options]

        Options:
          --format console|json|markdown|md   Report format (default: console)
          --output <file>                     Write report to file instead of stdout
          --force                             Overwrite existing report file
          --depth fast|standard|deep          Scan depth (default: fast)
          --profile <name>                    Trust profile (default: ProductionDependency)

        Supported profiles:
          Personal, ProductionDependency, EnterpriseDependency,
          CiCdTool, SecuritySensitiveDependency, ContainerDependency
          Common aliases: production, enterprise, ci-cd, security, container

        Exit codes:
          0   Scan completed, no blocking decision
          1   CLI usage error
          2   Input/output error
          3   Scan completed with AvoidAsProductionDependency decision
        """);
    }
}

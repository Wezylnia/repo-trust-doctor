using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;
using RepoTrustDoctor.Reporting;
using RepoTrustDoctor.Shared;

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

internal static partial class CliProgram
{
    private static readonly string[] SupportedFormats = ["console", "json", "markdown", "md", "sarif"];
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

        if (string.Equals(args[0], "benchmark", StringComparison.OrdinalIgnoreCase))
        {
            return await RunBenchmarkAsync(args, cancellationToken);
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
            "console" => ConsoleSummaryWriter.Build(scan),
            _ => throw new ArgumentException($"Unsupported format: {options.Format}")
        };

        var outputExitCode = await WriteOutputAsync(output, options.OutputPath, options.ForceOutput, cancellationToken);
        if (outputExitCode != 0)
        {
            return outputExitCode;
        }

        return ComputeExitCode(scan, options);
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

    private static bool TryParseTrustProfile(string profileValue, out TrustProfile profile)
    {
        if (Enum.TryParse(profileValue, ignoreCase: true, out profile))
        {
            profile = TrustProfileCatalog.Normalize(profile);
            return true;
        }

        return SupportedProfileAliases.TryGetValue(profileValue, out profile);
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
          repo-trust-doctor benchmark <path-or-url> [options]

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

        Benchmark options:
          --iterations <count>                Measured scans (default: 5)
          --warmup <count>                    Warm-up scans (default: 1)
          --depth fast|standard|deep          Scan depth (default: standard)
          --profile <name>                    Trust profile (default: ProductionDependency)

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

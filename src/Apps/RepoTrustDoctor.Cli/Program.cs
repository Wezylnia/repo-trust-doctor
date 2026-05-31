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

internal static class CliProgram
{
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

        var target = args.Length > 1 ? args[1] : ".";
        var format = ReadOption(args, "--format") ?? "console";
        var outputPath = ReadOption(args, "--output");
        var depth = ParseDepth(ReadOption(args, "--depth") ?? "fast");

        IRepositoryAnalyzer[] analyzers =
        [
            new RepositoryHealthAnalyzer(),
            new GitHubActionsBasicAnalyzer(),
            new SecretQuickScanAnalyzer(),
            new DockerBasicAnalyzer()
        ];

        using var workspace = await PrepareWorkspaceAsync(target, cancellationToken);
        var orchestrator = new ScanOrchestrator(analyzers, new AnalyzerExecutor(), new TrustScorer());
        var scan = await orchestrator.RunAsync(target, workspace.Path, depth, "ProductionDependency", cancellationToken);

        var output = format.ToLowerInvariant() switch
        {
            "json" => new JsonReportWriter().Write(scan),
            "markdown" or "md" => new MarkdownReportWriter().Write(scan),
            "console" => BuildConsoleSummary(scan),
            _ => throw new ArgumentException($"Unsupported format: {format}")
        };

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine(output);
        }
        else
        {
            var fullOutputPath = Path.GetFullPath(outputPath);
            var outputDirectory = Path.GetDirectoryName(fullOutputPath);
            if (!string.IsNullOrEmpty(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            await File.WriteAllTextAsync(fullOutputPath, output, cancellationToken);
            Console.WriteLine($"Report written to {fullOutputPath}");
        }

        return scan.Score.Decision.Kind == FinalDecisionKind.AvoidAsProductionDependency ? 3 : 0;
    }

    private static Task<RepositoryWorkspace> PrepareWorkspaceAsync(string target, CancellationToken cancellationToken)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return RepositoryWorkspace.CloneFromUrlAsync(target, cancellationToken);
        }

        return Task.FromResult(RepositoryWorkspace.ForLocalPath(target));
    }

    private static string? ReadOption(string[] args, string name)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private static AnalysisDepth ParseDepth(string value) => value.ToLowerInvariant() switch
    {
        "fast" => AnalysisDepth.Fast,
        "standard" => AnalysisDepth.Standard,
        "deep" => AnalysisDepth.Deep,
        _ => throw new ArgumentException($"Unsupported scan depth: {value}")
    };

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
          repo-trust-doctor scan <path-or-url> [--format console|json|markdown] [--output file] [--depth fast|standard|deep]
        """);
    }
}

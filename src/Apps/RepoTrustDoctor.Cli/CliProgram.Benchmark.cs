using System.Diagnostics;
using RepoTrustDoctor.Application.Scanning;
using RepoTrustDoctor.Domain;
using RepoTrustDoctor.Infrastructure.Scanning;

internal static partial class CliProgram
{
    internal static async Task<int> RunBenchmarkAsync(string[] args, CancellationToken cancellationToken)
    {
        if (!TryParseBenchmarkOptions(args, out var options, out var error))
        {
            Console.Error.WriteLine(error);
            return 1;
        }

        var runner = new DefaultRepositoryScanRunner();
        var durations = new List<double>();
        var moduleDurations = new Dictionary<string, List<double>>(StringComparer.OrdinalIgnoreCase);
        RepositoryScan? lastScan = null;
        var totalRuns = options.Warmup + options.Iterations;

        for (var run = 0; run < totalRuns; run++)
        {
            var stopwatch = Stopwatch.StartNew();
            var scan = await runner.RunAsync(
                new ScanRequestOptions(options.Target, options.Depth, options.TrustProfile, UseIncrementalCache: false),
                cancellationToken);
            stopwatch.Stop();
            lastScan = scan;
            if (run < options.Warmup) continue;

            durations.Add(stopwatch.Elapsed.TotalMilliseconds);
            foreach (var module in scan.Modules)
            {
                if (!moduleDurations.TryGetValue(module.DisplayName, out var values))
                {
                    values = [];
                    moduleDurations[module.DisplayName] = values;
                }

                values.Add((module.CompletedAt - module.StartedAt).TotalMilliseconds);
            }
        }

        durations.Sort();
        Console.WriteLine("Repository Trust Doctor");
        Console.WriteLine("Benchmark");
        Console.WriteLine($"Target: {options.Target}");
        Console.WriteLine($"Profile: {options.TrustProfile}, depth: {options.Depth}");
        Console.WriteLine($"Runs: {options.Iterations} measured, {options.Warmup} warm-up");
        Console.WriteLine($"Median: {Percentile(durations, 0.50):0.0} ms");
        Console.WriteLine($"P95: {Percentile(durations, 0.95):0.0} ms");
        Console.WriteLine($"Min / max: {durations[0]:0.0} / {durations[^1]:0.0} ms");
        Console.WriteLine($"Last result: {lastScan!.Score.Overall}/100, {lastScan.Score.Decision.Kind}, {lastScan.Findings.Count} findings");
        Console.WriteLine();
        Console.WriteLine("Slowest analyzer medians:");
        foreach (var module in moduleDurations
                     .Select(item => new { item.Key, Median = Percentile(item.Value.Order().ToArray(), 0.50) })
                     .OrderByDescending(item => item.Median)
                     .Take(10))
        {
            Console.WriteLine($"- {module.Key}: {module.Median:0.0} ms");
        }

        return 0;
    }

    private static bool TryParseBenchmarkOptions(
        string[] args,
        out BenchmarkOptions options,
        out string error)
    {
        options = default!;
        var target = ".";
        var hasTarget = false;
        var iterations = 5;
        var warmup = 1;
        var depth = AnalysisDepth.Standard;
        var profile = TrustProfile.ProductionDependency;
        error = string.Empty;

        for (var index = 1; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument is "--iterations" or "--warmup" or "--depth" or "--profile")
            {
                if (!TryReadOptionValue(args, ref index, argument, out var value, out error)) return false;
                if (argument == "--iterations" && (!int.TryParse(value, out iterations) || iterations is < 1 or > 100))
                {
                    error = "--iterations must be between 1 and 100.";
                    return false;
                }

                if (argument == "--warmup" && (!int.TryParse(value, out warmup) || warmup is < 0 or > 20))
                {
                    error = "--warmup must be between 0 and 20.";
                    return false;
                }

                if (argument == "--depth" && !Enum.TryParse(value, true, out depth))
                {
                    error = $"Unsupported benchmark depth: {value}.";
                    return false;
                }

                if (argument == "--profile" && !TryParseTrustProfile(value, out profile))
                {
                    error = $"Unsupported benchmark profile: {value}.";
                    return false;
                }

                continue;
            }

            if (argument.StartsWith('-'))
            {
                error = $"Unknown benchmark option: {argument}.";
                return false;
            }

            if (hasTarget)
            {
                error = $"Unexpected benchmark argument: {argument}.";
                return false;
            }

            target = argument;
            hasTarget = true;
        }

        options = new BenchmarkOptions(target, iterations, warmup, depth, profile);
        return true;
    }

    private static double Percentile(IReadOnlyList<double> orderedValues, double percentile)
    {
        if (orderedValues.Count == 0) return 0;
        var index = (int)Math.Ceiling(percentile * orderedValues.Count) - 1;
        return orderedValues[Math.Clamp(index, 0, orderedValues.Count - 1)];
    }

    private sealed record BenchmarkOptions(
        string Target,
        int Iterations,
        int Warmup,
        AnalysisDepth Depth,
        TrustProfile TrustProfile);
}

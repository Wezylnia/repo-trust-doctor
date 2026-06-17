using System.Globalization;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Scoring;

internal enum ScanCompletenessLevel
{
    Complete,
    Partial,
    Incomplete
}

internal sealed record ScanCompletenessAssessment(
    ScanCompletenessLevel Level,
    IReadOnlyDictionary<AnalysisCategory, ScanCompletenessLevel> Categories,
    IReadOnlyList<string> Reasons)
{
    internal static ScanCompletenessAssessment Complete { get; } =
        new(ScanCompletenessLevel.Complete, new Dictionary<AnalysisCategory, ScanCompletenessLevel>(), []);
}

internal static class ScanCompletenessEvaluator
{
    internal static ScanCompletenessAssessment Evaluate(IReadOnlyCollection<ScanModule> modules)
    {
        if (modules.Count == 0)
        {
            return ScanCompletenessAssessment.Complete;
        }

        var categoryLevels = new Dictionary<AnalysisCategory, ScanCompletenessLevel>();
        var reasons = new List<string>();

        foreach (var module in modules)
        {
            var level = EvaluateModule(module);
            if (!categoryLevels.TryGetValue(module.Category, out var current) || level > current)
            {
                categoryLevels[module.Category] = level;
            }

            if (level != ScanCompletenessLevel.Complete)
            {
                reasons.Add(Describe(module, level));
            }
        }

        return new ScanCompletenessAssessment(
            categoryLevels.Values.DefaultIfEmpty(ScanCompletenessLevel.Complete).Max(),
            categoryLevels,
            reasons.Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToArray());
    }

    private static ScanCompletenessLevel EvaluateModule(ScanModule module)
    {
        if (module.Status is ModuleStatus.Failed or ModuleStatus.TimedOut or ModuleStatus.Cancelled or
            ModuleStatus.Skipped or ModuleStatus.Waiting or ModuleStatus.Running)
        {
            return ScanCompletenessLevel.Incomplete;
        }

        var warningDetails = module.WarningDetails ?? ClassifyLegacyWarnings(module.Warnings);
        if (HasPartialCoverageMetric(module.Metrics) ||
            warningDetails.Any(warning => warning.AffectsCoverage) ||
            (module.Status == ModuleStatus.CompletedWithWarnings && warningDetails.Count == 0 && (module.Warnings?.Count ?? 0) == 0))
        {
            return ScanCompletenessLevel.Partial;
        }

        return ScanCompletenessLevel.Complete;
    }

    private static IReadOnlyList<ScanWarning> ClassifyLegacyWarnings(IReadOnlyList<string>? warnings)
    {
        if (warnings is null || warnings.Count == 0)
        {
            return [];
        }

        return warnings
            .Select(warning =>
            {
                var normalized = warning.ToLowerInvariant();
                var affectsCoverage =
                    normalized.Contains("truncated", StringComparison.Ordinal) ||
                    normalized.Contains("skipped", StringComparison.Ordinal) ||
                    normalized.Contains("too large", StringComparison.Ordinal) ||
                    normalized.Contains("could not parse", StringComparison.Ordinal) ||
                    normalized.Contains("could not read", StringComparison.Ordinal) ||
                    normalized.Contains("could not resolve", StringComparison.Ordinal) ||
                    normalized.Contains("could not load", StringComparison.Ordinal) ||
                    normalized.Contains("timeout", StringComparison.Ordinal) ||
                    normalized.Contains("timed out", StringComparison.Ordinal) ||
                    normalized.Contains("partial", StringComparison.Ordinal) ||
                    normalized.Contains("incomplete", StringComparison.Ordinal) ||
                    normalized.Contains("inconclusive", StringComparison.Ordinal) ||
                    normalized.Contains("unsupported", StringComparison.Ordinal) ||
                    normalized.Contains("outside the repository", StringComparison.Ordinal) ||
                    normalized.Contains("include limit", StringComparison.Ordinal);
                return new ScanWarning(
                    affectsCoverage ? ScanWarningKind.PartialCoverage : ScanWarningKind.Informational,
                    warning,
                    affectsCoverage);
            })
            .ToArray();
    }

    private static bool HasPartialCoverageMetric(IReadOnlyDictionary<string, string>? metrics)
    {
        if (metrics is null)
        {
            return false;
        }

        foreach (var (key, rawValue) in metrics)
        {
            if (key.EndsWith(".truncated", StringComparison.OrdinalIgnoreCase) &&
                bool.TryParse(rawValue, out var truncated) &&
                truncated)
            {
                return true;
            }

            if (key.EndsWith(".coverage.percent", StringComparison.OrdinalIgnoreCase) &&
                double.TryParse(rawValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var coverage) &&
                coverage < 100)
            {
                return true;
            }

            if ((key.EndsWith(".incomplete.count", StringComparison.OrdinalIgnoreCase) ||
                 key.EndsWith(".skipped.count", StringComparison.OrdinalIgnoreCase) ||
                 key.EndsWith(".unsupported.count", StringComparison.OrdinalIgnoreCase)) &&
                long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) &&
                count > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string Describe(ScanModule module, ScanCompletenessLevel level)
    {
        var detail = module.ErrorMessage ??
                     module.WarningDetails?.FirstOrDefault(warning => warning.AffectsCoverage)?.Message ??
                     module.Warnings?.FirstOrDefault() ??
                     (level == ScanCompletenessLevel.Incomplete
                         ? $"module ended with status {module.Status}"
                         : "module reported partial coverage");

        return $"{module.DisplayName}: {detail}";
    }
}

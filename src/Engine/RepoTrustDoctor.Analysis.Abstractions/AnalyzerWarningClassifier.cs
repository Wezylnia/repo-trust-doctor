using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analysis.Abstractions;

public static class AnalyzerWarningClassifier
{
    public static IReadOnlyList<ScanWarning> Classify(IReadOnlyList<string>? warnings)
    {
        if (warnings is null || warnings.Count == 0)
        {
            return [];
        }

        return warnings
            .Where(warning => !string.IsNullOrWhiteSpace(warning))
            .Select(Classify)
            .ToArray();
    }

    public static ScanWarning Classify(string warning)
    {
        var normalized = warning.ToLowerInvariant();

        if (normalized.Contains("stale", StringComparison.Ordinal) &&
            normalized.Contains("complete results", StringComparison.Ordinal))
        {
            return new ScanWarning(ScanWarningKind.StaleData, warning, AffectsCoverage: false);
        }

        if (normalized.Contains("truncated", StringComparison.Ordinal) ||
            normalized.Contains("skipped", StringComparison.Ordinal) ||
            normalized.Contains("too large", StringComparison.Ordinal) ||
            normalized.Contains("partial", StringComparison.Ordinal) ||
            normalized.Contains("incomplete", StringComparison.Ordinal) ||
            normalized.Contains("inconclusive", StringComparison.Ordinal) ||
            normalized.Contains("outside the repository", StringComparison.Ordinal) ||
            normalized.Contains("include limit", StringComparison.Ordinal))
        {
            return new ScanWarning(ScanWarningKind.PartialCoverage, warning, AffectsCoverage: true);
        }

        if (normalized.Contains("could not parse", StringComparison.Ordinal) ||
            normalized.Contains("could not read", StringComparison.Ordinal) ||
            normalized.Contains("could not resolve", StringComparison.Ordinal) ||
            normalized.Contains("could not load", StringComparison.Ordinal) ||
            normalized.Contains("not readable", StringComparison.Ordinal) ||
            normalized.Contains("unsupported", StringComparison.Ordinal))
        {
            return new ScanWarning(ScanWarningKind.UnsupportedInput, warning, AffectsCoverage: true);
        }

        if (normalized.Contains("timed out", StringComparison.Ordinal) ||
            normalized.Contains("timeout", StringComparison.Ordinal) ||
            normalized.Contains("rate-limited", StringComparison.Ordinal) ||
            normalized.Contains("server error", StringComparison.Ordinal) ||
            normalized.Contains("temporarily", StringComparison.Ordinal) ||
            normalized.Contains("blocked", StringComparison.Ordinal) ||
            normalized.Contains("rejected", StringComparison.Ordinal))
        {
            return new ScanWarning(ScanWarningKind.TransientFailure, warning, AffectsCoverage: true);
        }

        if (normalized.Contains("stale", StringComparison.Ordinal))
        {
            return new ScanWarning(ScanWarningKind.StaleData, warning, AffectsCoverage: false);
        }

        return new ScanWarning(ScanWarningKind.Informational, warning, AffectsCoverage: false);
    }
}

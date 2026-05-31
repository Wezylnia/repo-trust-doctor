using System.Security.Cryptography;
using System.Text;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Reporting;

public static class FindingFingerprinter
{
    public static IReadOnlyList<Finding> AddFingerprints(IReadOnlyList<Finding> findings)
    {
        return findings
            .Select(finding => finding with { Fingerprint = Compute(finding) })
            .ToArray();
    }

    public static string Compute(Finding finding)
    {
        var input = BuildInput(finding);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string BuildInput(Finding finding)
    {
        var builder = new StringBuilder();
        AppendPart(builder, Normalize(finding.RuleId));
        AppendPart(builder, finding.Category.ToString().ToLowerInvariant());

        var evidenceParts = finding.Evidence
            .Select(evidence => new
            {
                Kind = Normalize(evidence.Kind),
                FilePath = NormalizePath(evidence.FilePath),
                LineNumber = evidence.LineNumber?.ToString() ?? string.Empty
            })
            .OrderBy(evidence => evidence.Kind, StringComparer.Ordinal)
            .ThenBy(evidence => evidence.FilePath, StringComparer.Ordinal)
            .ThenBy(evidence => evidence.LineNumber, StringComparer.Ordinal);

        foreach (var evidence in evidenceParts)
        {
            AppendPart(builder, evidence.Kind);
            AppendPart(builder, evidence.FilePath);
            AppendPart(builder, evidence.LineNumber);
        }

        return builder.ToString();
    }

    private static string NormalizePath(string? value)
    {
        return Normalize(value).Replace('\\', '/');
    }

    private static string Normalize(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();
    }

    private static void AppendPart(StringBuilder builder, string value)
    {
        builder.Append(value.Length);
        builder.Append(':');
        builder.Append(value);
        builder.Append('|');
    }
}
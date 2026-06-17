using System.Security.Cryptography;
using System.Text;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analysis.Abstractions;

public static class FindingIdentity
{
    public static IReadOnlyList<Finding> AddFingerprints(IReadOnlyList<Finding> findings)
    {
        var candidates = findings
            .Select((finding, index) => new FingerprintCandidate(index, finding, Compute(finding)))
            .ToArray();
        var fingerprints = new string[candidates.Length];

        foreach (var group in candidates.GroupBy(candidate => candidate.BaseFingerprint, StringComparer.Ordinal))
        {
            if (group.Count() == 1)
            {
                var candidate = group.Single();
                fingerprints[candidate.Index] = candidate.BaseFingerprint;
                continue;
            }

            var locationOccurrences = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var candidate in group
                         .OrderBy(item => BuildLocationInput(item.Finding), StringComparer.Ordinal)
                         .ThenBy(item => item.Index))
            {
                var location = BuildLocationInput(candidate.Finding);
                var occurrence = locationOccurrences.GetValueOrDefault(location);
                locationOccurrences[location] = occurrence + 1;
                fingerprints[candidate.Index] = Hash(
                    $"{candidate.BaseFingerprint}|collision|{location}|{occurrence}");
            }
        }

        return candidates
            .OrderBy(candidate => candidate.Index)
            .Select(candidate => candidate.Finding with { Fingerprint = fingerprints[candidate.Index] })
            .ToArray();
    }

    public static string Compute(Finding finding)
    {
        return Hash(BuildInput(finding));
    }

    private static string BuildInput(Finding finding)
    {
        var builder = new StringBuilder();
        AppendPart(builder, Normalize(finding.RuleId));
        AppendPart(builder, finding.Category.ToString().ToLowerInvariant());
        var identityKey = Normalize(finding.IdentityKey);
        if (!string.IsNullOrWhiteSpace(identityKey))
        {
            AppendPart(builder, identityKey);
            return builder.ToString();
        }

        AppendPart(builder, Normalize(finding.Title));

        var evidenceParts = finding.Evidence
            .Select(evidence => new
            {
                Kind = Normalize(evidence.Kind),
                FilePath = NormalizePath(evidence.FilePath)
            })
            .OrderBy(evidence => evidence.Kind, StringComparer.Ordinal)
            .ThenBy(evidence => evidence.FilePath, StringComparer.Ordinal);

        foreach (var evidence in evidenceParts)
        {
            AppendPart(builder, evidence.Kind);
            AppendPart(builder, evidence.FilePath);
        }

        var identityTags = finding.Tags?
            .Where(tag => !string.IsNullOrWhiteSpace(tag))
            .Select(Normalize)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray() ?? [];
        foreach (var tag in identityTags)
        {
            AppendPart(builder, tag);
        }

        return builder.ToString();
    }

    private static string BuildLocationInput(Finding finding)
    {
        var builder = new StringBuilder();
        foreach (var evidence in finding.Evidence
                     .Select(evidence => new
                     {
                         FilePath = NormalizePath(evidence.FilePath),
                         LineNumber = evidence.LineNumber ?? 0
                     })
                     .OrderBy(evidence => evidence.FilePath, StringComparer.Ordinal)
                     .ThenBy(evidence => evidence.LineNumber))
        {
            AppendPart(builder, evidence.FilePath);
            AppendPart(builder, evidence.LineNumber.ToString());
        }

        return builder.ToString();
    }

    private static string NormalizePath(string? value)
    {
        return Normalize(value).Replace('\\', '/');
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        var previousWasWhitespace = false;
        foreach (var c in value.Trim())
        {
            if (char.IsWhiteSpace(c))
            {
                if (!previousWasWhitespace)
                {
                    builder.Append(' ');
                    previousWasWhitespace = true;
                }

                continue;
            }

            builder.Append(char.ToLowerInvariant(c));
            previousWasWhitespace = false;
        }

        return builder.ToString();
    }

    private static void AppendPart(StringBuilder builder, string value)
    {
        builder.Append(value.Length);
        builder.Append(':');
        builder.Append(value);
        builder.Append('|');
    }

    private static string Hash(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed record FingerprintCandidate(int Index, Finding Finding, string BaseFingerprint);
}

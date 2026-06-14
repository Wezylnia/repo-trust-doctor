using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public static class PackageLicenseNormalizer
{
    private const int MaxExpressionLength = 120;
    private static readonly string[] PermissiveLicenses = ["MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC"];
    private static readonly string[] CopyleftLicenses = ["AGPL", "LGPL", "GPL"];

    public static NormalizedPackageLicense Normalize(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression.Length > MaxExpressionLength)
        {
            return new NormalizedPackageLicense(PackageLicenseFamily.Unknown, null, Truncate(expression), false, false);
        }

        var normalized = expression.Trim();
        var upper = normalized.ToUpperInvariant();
        var spdx = upper
            .Replace("APACHE 2.0", "APACHE-2.0", StringComparison.Ordinal)
            .Replace("BSD 2-CLAUSE", "BSD-2-CLAUSE", StringComparison.Ordinal)
            .Replace("BSD 3-CLAUSE", "BSD-3-CLAUSE", StringComparison.Ordinal);

        var permissiveId = FindLicenseId(spdx, PermissiveLicenses);
        var copyleftId = FindLicenseId(spdx, CopyleftLicenses);
        if (copyleftId is not null)
        {
            if (permissiveId is not null && IsPermissiveAlternative(spdx))
            {
                return new NormalizedPackageLicense(PackageLicenseFamily.Permissive, permissiveId, normalized, true, false);
            }

            return new NormalizedPackageLicense(PackageLicenseFamily.Copyleft, copyleftId, normalized, true, true);
        }

        if (permissiveId is not null)
        {
            return new NormalizedPackageLicense(PackageLicenseFamily.Permissive, permissiveId, normalized, true, false);
        }

        return new NormalizedPackageLicense(PackageLicenseFamily.Unknown, null, normalized, false, false);
    }

    private static string? FindLicenseId(string expression, IReadOnlyList<string> licenseIds)
    {
        foreach (var id in licenseIds)
        {
            if (ContainsLicenseToken(expression, id))
            {
                return id;
            }
        }

        return null;
    }

    private static bool ContainsLicenseToken(string expression, string id)
    {
        var start = 0;
        while (start < expression.Length)
        {
            var index = expression.IndexOf(id, start, StringComparison.Ordinal);
            if (index < 0)
            {
                return false;
            }

            var beforeBoundary = index == 0 || !char.IsLetterOrDigit(expression[index - 1]);
            var end = index + id.Length;
            var afterBoundary = end >= expression.Length || !char.IsLetterOrDigit(expression[end]);
            if (beforeBoundary && afterBoundary)
            {
                return true;
            }

            start = index + id.Length;
        }

        return false;
    }

    private static bool IsPermissiveAlternative(string expression) =>
        expression.Contains(" OR ", StringComparison.Ordinal) &&
        !expression.Contains(" AND ", StringComparison.Ordinal);

    private static string? Truncate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= MaxExpressionLength ? value : value[..MaxExpressionLength];
    }
}

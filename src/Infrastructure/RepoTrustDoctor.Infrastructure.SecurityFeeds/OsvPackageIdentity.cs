using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

internal static class OsvPackageIdentity
{
    public static bool Matches(
        string? advisoryEcosystem,
        string? advisoryPackageName,
        DependencyPackageInfo package)
    {
        var expectedEcosystem = OsvEcosystemNames.GetName(package.Ecosystem);
        return string.Equals(
                   advisoryEcosystem,
                   expectedEcosystem,
                   StringComparison.OrdinalIgnoreCase) &&
               NamesEqual(expectedEcosystem, advisoryPackageName, package.Name);
    }

    public static string NormalizeForLookup(string ecosystem, string packageName)
    {
        var trimmed = packageName.Trim();
        if (ecosystem.Equals("PyPI", StringComparison.OrdinalIgnoreCase))
        {
            return Regex.Replace(trimmed.ToLowerInvariant(), "[-_.]+", "-");
        }

        return IsCaseSensitive(ecosystem)
            ? trimmed
            : trimmed.ToLowerInvariant();
    }

    private static bool NamesEqual(
        string? ecosystem,
        string? left,
        string? right)
    {
        if (left is null || right is null)
        {
            return left == right;
        }

        if (ecosystem?.Equals("PyPI", StringComparison.OrdinalIgnoreCase) == true)
        {
            return string.Equals(
                NormalizeForLookup(ecosystem, left),
                NormalizeForLookup(ecosystem, right),
                StringComparison.Ordinal);
        }

        return string.Equals(
            left.Trim(),
            right.Trim(),
            IsCaseSensitive(ecosystem)
                ? StringComparison.Ordinal
                : StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCaseSensitive(string? ecosystem) =>
        ecosystem is "Go" or "Maven" or "SwiftURL";
}

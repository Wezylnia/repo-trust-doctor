using System.Numerics;

namespace RepoTrustDoctor.Infrastructure.SecurityFeeds;

internal sealed record OsvSemanticVersion(
    IReadOnlyList<BigInteger> Core,
    IReadOnlyList<string> Prerelease) : IComparable<OsvSemanticVersion>
{
    public static bool TryParse(string? value, out OsvSemanticVersion version)
    {
        version = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim();
        if (normalized.Length > 1 &&
            normalized[0] is 'v' or 'V' &&
            char.IsDigit(normalized[1]))
        {
            normalized = normalized[1..];
        }

        var buildIndex = normalized.IndexOf('+');
        if (buildIndex >= 0)
        {
            if (!IdentifiersAreValid(normalized[(buildIndex + 1)..], allowLeadingZero: true))
            {
                return false;
            }

            normalized = normalized[..buildIndex];
        }

        var prereleaseIndex = normalized.IndexOf('-');
        var coreText = prereleaseIndex < 0 ? normalized : normalized[..prereleaseIndex];
        if (prereleaseIndex >= 0 &&
            !IdentifiersAreValid(normalized[(prereleaseIndex + 1)..], allowLeadingZero: false))
        {
            return false;
        }

        var prerelease = prereleaseIndex < 0
            ? []
            : normalized[(prereleaseIndex + 1)..]
                .Split('.');
        var coreParts = coreText.Split('.');
        if (coreParts.Length is < 1 or > 3 ||
            coreParts.Any(part =>
                !IsNumericIdentifier(part, allowLeadingZero: false) ||
                !BigInteger.TryParse(part, out _)))
        {
            return false;
        }

        var core = coreParts
            .Select(BigInteger.Parse)
            .Concat(Enumerable.Repeat(BigInteger.Zero, 3 - coreParts.Length))
            .ToArray();
        version = new OsvSemanticVersion(
            core,
            prerelease);
        return true;
    }

    public int CompareTo(OsvSemanticVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        var coreLength = Math.Max(Core.Count, other.Core.Count);
        for (var index = 0; index < coreLength; index++)
        {
            var left = index < Core.Count ? Core[index] : BigInteger.Zero;
            var right = index < other.Core.Count ? other.Core[index] : BigInteger.Zero;
            var comparison = left.CompareTo(right);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        if (Prerelease.Count == 0 || other.Prerelease.Count == 0)
        {
            return Prerelease.Count == other.Prerelease.Count
                ? 0
                : Prerelease.Count == 0 ? 1 : -1;
        }

        var prereleaseLength = Math.Max(Prerelease.Count, other.Prerelease.Count);
        for (var index = 0; index < prereleaseLength; index++)
        {
            if (index >= Prerelease.Count)
            {
                return -1;
            }

            if (index >= other.Prerelease.Count)
            {
                return 1;
            }

            var comparison = CompareIdentifier(Prerelease[index], other.Prerelease[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }

    private static int CompareIdentifier(string left, string right)
    {
        var leftNumeric = BigInteger.TryParse(left, out var leftNumber);
        var rightNumeric = BigInteger.TryParse(right, out var rightNumber);
        if (leftNumeric && rightNumeric)
        {
            return leftNumber.CompareTo(rightNumber);
        }

        if (leftNumeric != rightNumeric)
        {
            return leftNumeric ? -1 : 1;
        }

        return string.Compare(left, right, StringComparison.Ordinal);
    }

    private static bool IdentifiersAreValid(string value, bool allowLeadingZero)
    {
        var identifiers = value.Split('.');
        return identifiers.Length > 0 &&
               identifiers.All(identifier =>
                   identifier.Length > 0 &&
                   identifier.All(character =>
                       char.IsAsciiLetterOrDigit(character) || character == '-') &&
                   (!identifier.All(char.IsDigit) ||
                    IsNumericIdentifier(identifier, allowLeadingZero)));
    }

    private static bool IsNumericIdentifier(string value, bool allowLeadingZero) =>
        value.Length > 0 &&
        value.All(char.IsDigit) &&
        (allowLeadingZero || value.Length == 1 || value[0] != '0');
}

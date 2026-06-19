namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

internal sealed class NuGetVersionStringComparer : IComparer<string?>
{
    public static NuGetVersionStringComparer Instance { get; } = new();

    public int Compare(string? x, string? y)
    {
        if (string.Equals(x, y, StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        if (TryParseNuGetVersion(x, out var left) && TryParseNuGetVersion(y, out var right))
        {
            return left.CompareTo(right);
        }

        return StringComparer.OrdinalIgnoreCase.Compare(x, y);
    }

    private static bool TryParseNuGetVersion(string? version, out NuGetVersionKey key)
    {
        key = default!;
        if (string.IsNullOrWhiteSpace(version))
        {
            return false;
        }

        var normalized = version.Trim();
        if (normalized.Length > 1 &&
            normalized[0] is 'v' or 'V' &&
            char.IsDigit(normalized[1]))
        {
            normalized = normalized[1..];
        }

        var metadataIndex = normalized.IndexOf('+', StringComparison.Ordinal);
        if (metadataIndex >= 0)
        {
            normalized = normalized[..metadataIndex];
        }

        var prereleaseIndex = normalized.IndexOf('-', StringComparison.Ordinal);
        var releaseText = prereleaseIndex >= 0 ? normalized[..prereleaseIndex] : normalized;
        var prereleaseText = prereleaseIndex >= 0 ? normalized[(prereleaseIndex + 1)..] : string.Empty;
        var releaseParts = releaseText.Split('.', StringSplitOptions.TrimEntries);
        if (releaseParts.Length is < 1 or > 4 || releaseParts.Any(string.IsNullOrEmpty))
        {
            return false;
        }

        var release = new List<long>(releaseParts.Length);
        foreach (var part in releaseParts)
        {
            if (!long.TryParse(part, out var number) || number < 0)
            {
                return false;
            }

            release.Add(number);
        }

        IReadOnlyList<string> prerelease = [];
        if (prereleaseIndex >= 0)
        {
            if (string.IsNullOrWhiteSpace(prereleaseText))
            {
                return false;
            }

            var prereleaseParts = prereleaseText.Split('.', StringSplitOptions.TrimEntries);
            if (prereleaseParts.Any(part =>
                    string.IsNullOrEmpty(part) ||
                    part.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-')))
            {
                return false;
            }

            prerelease = prereleaseParts;
        }

        key = new NuGetVersionKey(release, prerelease);
        return true;
    }

    private sealed record NuGetVersionKey(
        IReadOnlyList<long> Release,
        IReadOnlyList<string> Prerelease) : IComparable<NuGetVersionKey>
    {
        public int CompareTo(NuGetVersionKey? other)
        {
            if (other is null)
            {
                return 1;
            }

            var releaseLength = Math.Max(Release.Count, other.Release.Count);
            for (var i = 0; i < releaseLength; i++)
            {
                var left = i < Release.Count ? Release[i] : 0;
                var right = i < other.Release.Count ? other.Release[i] : 0;
                var releaseComparison = left.CompareTo(right);
                if (releaseComparison != 0)
                {
                    return releaseComparison;
                }
            }

            if (Prerelease.Count == 0 && other.Prerelease.Count == 0)
            {
                return 0;
            }

            if (Prerelease.Count == 0)
            {
                return 1;
            }

            if (other.Prerelease.Count == 0)
            {
                return -1;
            }

            var prereleaseLength = Math.Max(Prerelease.Count, other.Prerelease.Count);
            for (var i = 0; i < prereleaseLength; i++)
            {
                if (i >= Prerelease.Count)
                {
                    return -1;
                }

                if (i >= other.Prerelease.Count)
                {
                    return 1;
                }

                var leftPart = Prerelease[i];
                var rightPart = other.Prerelease[i];
                var leftIsNumber = long.TryParse(leftPart, out var leftNumber);
                var rightIsNumber = long.TryParse(rightPart, out var rightNumber);
                var comparison = (leftIsNumber, rightIsNumber) switch
                {
                    (true, true) => leftNumber.CompareTo(rightNumber),
                    (true, false) => -1,
                    (false, true) => 1,
                    _ => StringComparer.OrdinalIgnoreCase.Compare(leftPart, rightPart)
                };

                if (comparison != 0)
                {
                    return comparison;
                }
            }

            return 0;
        }
    }
}

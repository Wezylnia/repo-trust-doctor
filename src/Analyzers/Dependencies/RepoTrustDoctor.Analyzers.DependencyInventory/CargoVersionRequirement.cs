namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal static class CargoVersionRequirement
{
    public static bool TrySelectSingle(
        string? requirement,
        IReadOnlyCollection<string> candidates,
        out string version)
    {
        version = string.Empty;
        if (string.IsNullOrWhiteSpace(requirement) || candidates.Count == 0)
        {
            return false;
        }

        var matches = candidates
            .Where(candidate => Matches(requirement, candidate))
            .Take(2)
            .ToArray();
        if (matches.Length != 1)
        {
            return false;
        }

        version = matches[0];
        return true;
    }

    private static bool Matches(string requirement, string candidateText)
    {
        if (!CargoSemanticVersion.TryParse(candidateText, out var candidate))
        {
            return false;
        }

        var normalized = requirement.Trim();
        if (normalized.Contains("||", StringComparison.Ordinal))
        {
            return false;
        }

        if (candidate.Prerelease is not null && !normalized.Contains('-', StringComparison.Ordinal))
        {
            return false;
        }

        var clauses = normalized.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return clauses.Length > 1
            ? clauses.All(clause => MatchesClause(clause, candidate))
            : MatchesClause(normalized, candidate);
    }

    private static bool MatchesClause(string clause, CargoSemanticVersion candidate)
    {
        clause = clause.Trim();
        if (clause.Length == 0 || clause == "*")
        {
            return true;
        }

        foreach (var comparison in new[] { ">=", "<=", ">", "<", "=" })
        {
            if (!clause.StartsWith(comparison, StringComparison.Ordinal))
            {
                continue;
            }

            return TryReadVersion(clause[comparison.Length..], out var boundary, out _) &&
                   Compare(candidate, boundary, comparison);
        }

        if (clause.StartsWith('~'))
        {
            return TryReadVersion(clause[1..], out var minimum, out var components) &&
                   candidate.CompareTo(minimum) >= 0 &&
                   candidate.CompareTo(TildeUpperBound(minimum, components)) < 0;
        }

        var caret = clause.StartsWith('^');
        var value = caret ? clause[1..] : clause;
        if (value.Contains('*', StringComparison.OrdinalIgnoreCase) ||
            value.Contains('x', StringComparison.OrdinalIgnoreCase))
        {
            return TryMatchWildcard(value, candidate);
        }

        return TryReadVersion(value, out var lower, out var componentCount) &&
               candidate.CompareTo(lower) >= 0 &&
               candidate.CompareTo(CaretUpperBound(lower, componentCount)) < 0;
    }

    private static bool Compare(
        CargoSemanticVersion candidate,
        CargoSemanticVersion boundary,
        string comparison) =>
        comparison switch
        {
            ">=" => candidate.CompareTo(boundary) >= 0,
            "<=" => candidate.CompareTo(boundary) <= 0,
            ">" => candidate.CompareTo(boundary) > 0,
            "<" => candidate.CompareTo(boundary) < 0,
            "=" => candidate.CompareTo(boundary) == 0,
            _ => false
        };

    private static bool TryMatchWildcard(string value, CargoSemanticVersion candidate)
    {
        var parts = value.Split('.');
        if (parts.Length is 0 or > 3)
        {
            return false;
        }

        if (IsWildcard(parts[0]))
        {
            return true;
        }

        if (!int.TryParse(parts[0], out var major) || candidate.Major != major)
        {
            return false;
        }

        if (parts.Length == 1 || IsWildcard(parts[1]))
        {
            return true;
        }

        return int.TryParse(parts[1], out var minor) &&
               candidate.Minor == minor &&
               (parts.Length == 2 || IsWildcard(parts[2]) ||
                int.TryParse(parts[2], out var patch) && candidate.Patch == patch);
    }

    private static bool IsWildcard(string value) =>
        value is "*" ||
        value.Equals("x", StringComparison.OrdinalIgnoreCase);

    private static bool TryReadVersion(
        string text,
        out CargoSemanticVersion version,
        out int componentCount)
    {
        version = default!;
        var core = text.Trim();
        var prereleaseIndex = core.IndexOf('-');
        var numeric = prereleaseIndex >= 0 ? core[..prereleaseIndex] : core;
        componentCount = numeric.Split('.', StringSplitOptions.RemoveEmptyEntries).Length;
        return componentCount is >= 1 and <= 3 &&
               CargoSemanticVersion.TryParse(core, out version);
    }

    private static CargoSemanticVersion CaretUpperBound(
        CargoSemanticVersion version,
        int componentCount)
    {
        if (componentCount == 1)
        {
            return new CargoSemanticVersion(version.Major + 1, 0, 0, null);
        }

        if (version.Major > 0)
        {
            return new CargoSemanticVersion(version.Major + 1, 0, 0, null);
        }

        if (componentCount == 2 || version.Minor > 0)
        {
            return new CargoSemanticVersion(0, version.Minor + 1, 0, null);
        }

        return new CargoSemanticVersion(0, 0, version.Patch + 1, null);
    }

    private static CargoSemanticVersion TildeUpperBound(
        CargoSemanticVersion version,
        int componentCount) =>
        componentCount == 1
            ? new CargoSemanticVersion(version.Major + 1, 0, 0, null)
            : new CargoSemanticVersion(version.Major, version.Minor + 1, 0, null);
}

internal sealed record CargoSemanticVersion(
    int Major,
    int Minor,
    int Patch,
    string? Prerelease) : IComparable<CargoSemanticVersion>
{
    public static bool TryParse(string? value, out CargoSemanticVersion version)
    {
        version = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim();
        var metadataIndex = normalized.IndexOf('+');
        if (metadataIndex >= 0)
        {
            normalized = normalized[..metadataIndex];
        }

        string? prerelease = null;
        var prereleaseIndex = normalized.IndexOf('-');
        if (prereleaseIndex >= 0)
        {
            prerelease = normalized[(prereleaseIndex + 1)..];
            normalized = normalized[..prereleaseIndex];
            if (prerelease.Length == 0)
            {
                return false;
            }
        }

        var parts = normalized.Split('.');
        var minor = 0;
        var patch = 0;
        if (parts.Length is < 1 or > 3 ||
            !int.TryParse(parts[0], out var major) ||
            parts.Length > 1 && !int.TryParse(parts[1], out minor) ||
            parts.Length > 2 && !int.TryParse(parts[2], out patch))
        {
            return false;
        }

        version = new CargoSemanticVersion(
            major,
            parts.Length > 1 ? minor : 0,
            parts.Length > 2 ? patch : 0,
            prerelease);
        return true;
    }

    public int CompareTo(CargoSemanticVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        var core = Major.CompareTo(other.Major);
        if (core == 0)
        {
            core = Minor.CompareTo(other.Minor);
        }
        if (core == 0)
        {
            core = Patch.CompareTo(other.Patch);
        }
        if (core != 0)
        {
            return core;
        }

        if (Prerelease is null)
        {
            return other.Prerelease is null ? 0 : 1;
        }

        return other.Prerelease is null ? -1 : ComparePrerelease(Prerelease, other.Prerelease);
    }

    private static int ComparePrerelease(string left, string right)
    {
        var leftParts = left.Split('.');
        var rightParts = right.Split('.');
        for (var index = 0; index < Math.Min(leftParts.Length, rightParts.Length); index++)
        {
            var leftNumeric = int.TryParse(leftParts[index], out var leftNumber);
            var rightNumeric = int.TryParse(rightParts[index], out var rightNumber);
            int comparison;
            if (leftNumeric && rightNumeric)
            {
                comparison = leftNumber.CompareTo(rightNumber);
            }
            else if (leftNumeric != rightNumeric)
            {
                comparison = leftNumeric ? -1 : 1;
            }
            else
            {
                comparison = string.Compare(
                    leftParts[index],
                    rightParts[index],
                    StringComparison.Ordinal);
            }

            if (comparison != 0)
            {
                return comparison;
            }
        }

        return leftParts.Length.CompareTo(rightParts.Length);
    }
}

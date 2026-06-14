namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed record NpmSourceKind(string Kind, bool IsRemote, bool IsLocal);

internal sealed record NpmDependencySpec(
    string DeclaredName,
    string PackageName,
    string? RequestedSpec,
    string? EffectiveVersion,
    string? LockSelector,
    NpmSourceKind SourceKind,
    bool IsAlias);

internal static class NpmDependencySpecParser
{
    public static NpmDependencySpec Parse(string declaredName, string? requestedSpec)
    {
        var sourceKind = Classify(requestedSpec);
        if (!sourceKind.Kind.Equals("alias", StringComparison.OrdinalIgnoreCase) ||
            !TryParseAlias(requestedSpec, out var packageName, out var version))
        {
            return new NpmDependencySpec(
                declaredName,
                declaredName,
                requestedSpec,
                requestedSpec,
                requestedSpec,
                sourceKind,
                false);
        }

        return new NpmDependencySpec(
            declaredName,
            packageName,
            requestedSpec,
            version,
            requestedSpec,
            new NpmSourceKind("registry", false, false),
            true);
    }

    private static NpmSourceKind Classify(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return new NpmSourceKind("registry", false, false);
        }

        var value = version.Trim();
        if (value.StartsWith("git+", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("git://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("github:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            value.Contains(".git#", StringComparison.OrdinalIgnoreCase))
        {
            return new NpmSourceKind("remote", true, false);
        }

        return value.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("link:", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("portal:", StringComparison.OrdinalIgnoreCase)
            ? new NpmSourceKind("local", false, true)
            : value.StartsWith("npm:", StringComparison.OrdinalIgnoreCase)
                ? new NpmSourceKind("alias", false, false)
                : value.StartsWith("workspace:", StringComparison.OrdinalIgnoreCase)
                    ? new NpmSourceKind("workspace", false, false)
                    : new NpmSourceKind("registry", false, false);
    }

    private static bool TryParseAlias(string? value, out string packageName, out string? version)
    {
        packageName = string.Empty;
        version = null;
        if (string.IsNullOrWhiteSpace(value) ||
            !value.StartsWith("npm:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var aliasTarget = value["npm:".Length..].Trim();
        var separator = FindVersionSeparator(aliasTarget);
        if (separator < 0)
        {
            packageName = aliasTarget;
            return packageName.Length > 0;
        }

        packageName = aliasTarget[..separator];
        version = aliasTarget[(separator + 1)..];
        return packageName.Length > 0;
    }

    private static int FindVersionSeparator(string value)
    {
        if (!value.StartsWith('@'))
        {
            return value.LastIndexOf('@');
        }

        var slash = value.IndexOf('/');
        return slash < 0 ? -1 : value.LastIndexOf('@');
    }
}

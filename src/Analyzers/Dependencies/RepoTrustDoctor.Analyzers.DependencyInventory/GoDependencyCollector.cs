using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class GoDependencyCollector : IDependencyInventoryCollector
{
    public void Collect(AnalysisContext context, DependencyInventoryState state, CancellationToken cancellationToken)
    {
        foreach (var goMod in RepositoryFileSystem.EnumerateFiles(context.RepositoryPath, "go.mod"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeGoMod(context, goMod, state);
        }
    }

    private static void AnalyzeGoMod(AnalysisContext context, string filePath, DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, filePath);
        state.Manifests.Add(new DependencyManifestInfo(DependencyEcosystem.Go, relativePath, "go.mod"));

        var hasGoSum = HasGoSum(context, filePath);
        if (!hasGoSum)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP022",
                "Go module does not have a go.sum file",
                Severity.Medium,
                Confidence.High,
                "A go.mod file exists but no go.sum was found alongside it.",
                "package-manifest",
                "No go.sum file was found alongside go.mod.",
                relativePath,
                "Run 'go mod tidy' and commit go.sum to the repository for reproducible builds."));
        }

        if (!DependencyInventorySupport.TryReadText(filePath, out var content, state.Warnings, relativePath))
        {
            return;
        }

        var lines = DependencyInventorySupport.SplitLines(content);
        var inRequireBlock = false;
        string? modulePath = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (line is "require (" or "require(")
            {
                inRequireBlock = true;
                continue;
            }

            if (inRequireBlock && line == ")")
            {
                inRequireBlock = false;
                continue;
            }

            if (line.StartsWith("module ", StringComparison.Ordinal))
            {
                modulePath = line["module ".Length..].Trim();
                continue;
            }

            if (line.StartsWith("require ", StringComparison.Ordinal))
            {
                ParseSingleRequire(relativePath, line["require ".Length..].Trim(), state);
                continue;
            }

            if (inRequireBlock)
            {
                ParseSingleRequire(relativePath, line, state);
            }

            if (line.StartsWith("replace ", StringComparison.Ordinal))
            {
                state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                    "TRUST-DEP023",
                    "Go module uses replace directive",
                    Severity.Low,
                    Confidence.High,
                    "The go.mod file contains a replace directive.",
                    "go-replace-directive",
                    line,
                    relativePath,
                    "Review replace directives because they override resolved module versions."));
            }
        }

        if (modulePath != null && ModuleLooksPseudoVersion(modulePath, lines))
        {
            // Pseudo-version detection is done at the package level below
        }
    }

    private static bool HasGoSum(AnalysisContext context, string goModPath)
    {
        var directory = Path.GetDirectoryName(goModPath);
        if (directory == null)
        {
            return false;
        }

        var goSumPath = Path.Combine(directory, "go.sum");
        return File.Exists(goSumPath);
    }

    private static void ParseSingleRequire(string manifestPath, string line, DependencyInventoryState state)
    {
        // Format: module/path [version]
        // or: module/path v1.2.3
        // or: module/path v1.2.3 // indirect
        var trimmed = line.TrimEnd(')');

        var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 1)
        {
            return;
        }

        var modulePath = parts[0];
        var version = parts.Length > 1 ? parts[1] : null;
        var isIndirect = trimmed.Contains("// indirect", StringComparison.OrdinalIgnoreCase);

        // Skip Go toolchain and go directive lines
        if (modulePath is "go" or "toolchain")
        {
            return;
        }

        var isPinned = version != null && ExactGoVersionPattern().IsMatch(version);
        var isPseudoVersion = version != null && IsPseudoVersion(version);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (isIndirect)
        {
            metadata["directness"] = "indirect";
        }

        if (isPseudoVersion)
        {
            metadata["pseudoVersion"] = "true";
        }

        state.Packages.Add(new DependencyPackageInfo(
            DependencyEcosystem.Go,
            modulePath,
            version,
            DependencyScope.Unknown,
            manifestPath,
            null, // go.sum is not per-package
            !isIndirect,
            isPinned,
            false,
            metadata.Count > 0 ? metadata : null));

        if (!isPinned && version != null)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP024",
                "Go dependency uses a non-exact version",
                Severity.Medium,
                Confidence.High,
                $"Go dependency '{modulePath}' does not use an exact pinned version.",
                "go-require",
                $"Module '{modulePath}' has version '{version}'.",
                manifestPath,
                "Use exact versions with a committed go.sum for reproducible Go builds."));
        }

        if (isPseudoVersion)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP025",
                "Go dependency uses a pseudo-version",
                Severity.Low,
                Confidence.High,
                $"Go dependency '{modulePath}' references a pseudo-version.",
                "go-pseudo-version",
                $"Module '{modulePath}' has pseudo-version '{version}'.",
                manifestPath,
                "Prefer tagged releases over pseudo-versions and review pseudo-version origins."));
        }
    }

    private static bool IsPseudoVersion(string version) =>
        PseudoVersionPattern().IsMatch(version);

    private static bool ModuleLooksPseudoVersion(string modulePath, string[] lines) =>
        lines.Any(line => line.TrimStart().StartsWith("require ", StringComparison.Ordinal) &&
                          PseudoVersionPattern().IsMatch(line));

    [GeneratedRegex(@"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactGoVersionPattern();

    [GeneratedRegex(@"^v\d+\.\d+\.\d+-[0-9]{14}-[0-9a-f]{12}", RegexOptions.CultureInvariant)]
    private static partial Regex PseudoVersionPattern();
}

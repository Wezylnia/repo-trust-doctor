using System.Text;
using System.Text.RegularExpressions;
using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed record PythonRequirementSpec(
    string Name,
    string? Operator,
    string? Version);

internal sealed record PythonRequirementDeclaration(
    string RelativePath,
    PythonRequirementSpec Requirement,
    bool IsConstraint);

internal sealed record PythonRequirementGraph(
    IReadOnlyList<PythonRequirementDeclaration> Declarations,
    IReadOnlyList<string> IncludedFiles);

internal sealed record PythonResolvedRequirement(
    string RelativePath,
    PythonRequirementSpec Requirement,
    string? ConstraintPath,
    string? RequestedRequirement);

internal static class PythonRequirementResolver
{
    public static IEnumerable<PythonResolvedRequirement> Resolve(PythonRequirementGraph graph)
    {
        var constraints = graph.Declarations
            .Where(declaration => declaration.IsConstraint && IsExact(declaration.Requirement))
            .GroupBy(
                declaration => PythonRequirementParser.NormalizeName(declaration.Requirement.Name),
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last(), StringComparer.OrdinalIgnoreCase);

        foreach (var declaration in graph.Declarations.Where(declaration => !declaration.IsConstraint))
        {
            constraints.TryGetValue(
                PythonRequirementParser.NormalizeName(declaration.Requirement.Name),
                out var constraint);
            if (IsExact(declaration.Requirement) || constraint is null)
            {
                yield return new PythonResolvedRequirement(
                    declaration.RelativePath,
                    declaration.Requirement,
                    null,
                    null);
                continue;
            }

            yield return new PythonResolvedRequirement(
                declaration.RelativePath,
                new PythonRequirementSpec(
                    declaration.Requirement.Name,
                    constraint.Requirement.Operator,
                    constraint.Requirement.Version),
                constraint.RelativePath,
                Format(declaration.Requirement));
        }
    }

    private static bool IsExact(PythonRequirementSpec requirement) =>
        requirement.Operator is "==" or "===";

    private static string Format(PythonRequirementSpec requirement) =>
        $"{requirement.Name}{requirement.Operator}{requirement.Version}";
}

internal static partial class PythonRequirementParser
{
    public static bool TryParse(string line, out PythonRequirementSpec requirement)
    {
        requirement = default!;
        var trimmed = line.Trim();
        if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith('-'))
        {
            return false;
        }

        var match = RequirementPattern().Match(trimmed);
        if (!match.Success)
        {
            return false;
        }

        requirement = new PythonRequirementSpec(
            match.Groups["name"].Value,
            match.Groups["op"].Success ? match.Groups["op"].Value : null,
            match.Groups["version"].Success ? match.Groups["version"].Value : null);
        return true;
    }

    public static string NormalizeName(string name)
    {
        var builder = new StringBuilder(name.Length);
        var previousWasSeparator = false;
        foreach (var character in name.Trim())
        {
            if (character is '-' or '_' or '.')
            {
                if (!previousWasSeparator)
                {
                    builder.Append('-');
                    previousWasSeparator = true;
                }

                continue;
            }

            builder.Append(char.ToLowerInvariant(character));
            previousWasSeparator = false;
        }

        return builder.ToString();
    }

    [GeneratedRegex(@"^(?<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?<op>===|==|~=|!=|<=|>=|<|>)?\s*(?<version>[^\s;]+)?", RegexOptions.CultureInvariant)]
    private static partial Regex RequirementPattern();
}

internal static class PythonRequirementGraphReader
{
    private const int MaximumIncludeDepth = 16;

    public static PythonRequirementGraph Read(
        AnalysisContext context,
        string rootFile,
        List<string> warnings)
    {
        var declarations = new List<PythonRequirementDeclaration>();
        var includedFiles = new List<string>();
        var visited = new HashSet<string>(GetPathComparer());
        ReadFile(context, rootFile, false, 0, visited, declarations, includedFiles, warnings);
        return new PythonRequirementGraph(declarations, includedFiles);
    }

    private static void ReadFile(
        AnalysisContext context,
        string filePath,
        bool isConstraint,
        int depth,
        HashSet<string> visited,
        List<PythonRequirementDeclaration> declarations,
        List<string> includedFiles,
        List<string> warnings)
    {
        var fullPath = Path.GetFullPath(filePath);
        var relativePath = DependencyInventorySupport.Relative(context, fullPath);
        if (!IsInsideRepository(context.RepositoryPath, fullPath))
        {
            warnings.Add($"Skipped Python requirement include outside the repository: '{relativePath}'.");
            return;
        }

        if (depth > MaximumIncludeDepth)
        {
            warnings.Add($"Skipped Python requirement include '{relativePath}' after exceeding the {MaximumIncludeDepth}-level include limit.");
            return;
        }

        if (!visited.Add($"{fullPath}\u001f{isConstraint}"))
        {
            return;
        }

        if (!DependencyInventorySupport.TryReadText(fullPath, out var content, warnings, relativePath))
        {
            return;
        }

        if (depth > 0)
        {
            includedFiles.Add(relativePath);
        }

        foreach (var line in DependencyInventorySupport.SplitLines(content))
        {
            if (TryReadInclude(line, out var includePath, out var includeIsConstraint))
            {
                var resolved = ResolveIncludePath(fullPath, includePath);
                if (resolved is null || !File.Exists(resolved))
                {
                    warnings.Add($"Could not resolve Python requirement include '{includePath}' from '{relativePath}'.");
                    continue;
                }

                ReadFile(
                    context,
                    resolved,
                    includeIsConstraint,
                    depth + 1,
                    visited,
                    declarations,
                    includedFiles,
                    warnings);
                continue;
            }

            if (PythonRequirementParser.TryParse(line, out var requirement))
            {
                declarations.Add(new PythonRequirementDeclaration(relativePath, requirement, isConstraint));
            }
        }
    }

    private static bool TryReadInclude(string line, out string includePath, out bool isConstraint)
    {
        includePath = string.Empty;
        isConstraint = false;
        var trimmed = line.Trim();
        var prefixes = new[]
        {
            (Prefix: "--requirement", Constraint: false),
            (Prefix: "-r", Constraint: false),
            (Prefix: "--constraint", Constraint: true),
            (Prefix: "-c", Constraint: true)
        };

        foreach (var entry in prefixes)
        {
            if (!trimmed.StartsWith(entry.Prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var remainder = trimmed[entry.Prefix.Length..];
            if (remainder.Length > 0 && remainder[0] is not '=' && !char.IsWhiteSpace(remainder[0]))
            {
                continue;
            }

            includePath = remainder.TrimStart('=', ' ', '\t').Trim('"', '\'');
            isConstraint = entry.Constraint;
            return includePath.Length > 0;
        }

        return false;
    }

    private static string? ResolveIncludePath(string sourceFile, string includePath)
    {
        try
        {
            return Path.GetFullPath(Path.Combine(Path.GetDirectoryName(sourceFile)!, includePath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    private static bool IsInsideRepository(string repositoryPath, string candidatePath)
    {
        var root = Path.GetFullPath(repositoryPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return candidatePath.Equals(root, comparison) ||
               candidatePath.StartsWith(root + Path.DirectorySeparatorChar, comparison) ||
               candidatePath.StartsWith(root + Path.AltDirectorySeparatorChar, comparison);
    }

    private static StringComparer GetPathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}
